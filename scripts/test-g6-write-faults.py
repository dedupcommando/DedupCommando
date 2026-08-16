#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fault injection against the delivery's own write path.

`write_all()` is the only place that decides what a partial or a stalled write means, and neither
case can be produced by handing the program a funny file: the kernel writes what it is given.
So this drives the function directly with `os.write` replaced, in a subprocess of its own, and
looks at what the publication actually left on disk.

    test-g6-write-faults.py <delivery-dir> short   short positive writes must be completed
    test-g6-write-faults.py <delivery-dir> zero    a write that makes no progress must FAIL fast
    test-g6-write-faults.py <delivery-dir> publish a stalled publication must leave no final
    test-g6-write-faults.py <delivery-dir> claim   a lost race must not overwrite the state file

The `zero` and `publish` cases are the ones that hang when the no-progress check is removed, so
the caller runs this under a bounded timeout: an answer that never comes IS the failure.

The `claim` case is here for the same reason the others are: the interleaving it is about — the
state file appearing between the read and the write — cannot be produced from outside by running
two processes and hoping. So it is produced directly, by claiming a directory that is already
claimed, which is exactly what the losing process does.
"""

import importlib.util
import os
import sys
import tempfile


def load(delivery):
    path = os.path.join(delivery, "g6-publish-record.py")
    spec = importlib.util.spec_from_file_location("g6publish", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Patched:
    """os.write, replaced by something that behaves like a device having a bad day."""

    def __init__(self, module, behaviour):
        self.module = module
        self.behaviour = behaviour
        self.real = os.write
        self.written = bytearray()

    def __enter__(self):
        real, written, behaviour = self.real, self.written, self.behaviour

        def fake(fd, data):
            if behaviour == "short":
                # One byte at a time: every call makes progress, and write_all must keep going
                # until the whole buffer has landed.
                n = real(fd, data[:1])
                written.extend(data[:n])
                return n
            if behaviour == "zero":
                # The pathological case: no error, no progress, for ever.
                return 0
            return real(fd, data)

        os.write = fake
        return self

    def __exit__(self, *exc):
        os.write = self.real
        return False


def case_short(module):
    payload = b"a record that has to land in full\n" * 7
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "out")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with Patched(module, "short"):
                module.write_all(fd, payload, target)
        finally:
            os.close(fd)
        with open(target, "rb") as fh:
            landed = fh.read()
    if landed != payload:
        print(f"write-short -> {len(landed)} of {len(payload)} bytes landed")
        return 1
    print("write-short -> the whole buffer landed")
    return 0


def case_zero(module):
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "out")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with Patched(module, "zero"):
                try:
                    module.write_all(fd, b"x" * 4096, target)
                except OSError as exc:
                    print(f"write-zero -> refused: {exc}")
                    return 0
        finally:
            os.close(fd)
    print("write-zero -> a write that made no progress was accepted")
    return 1


def case_publish(module):
    """The whole publication under a stalled write: it must fail, and it must leave no final
    record and no temporary behind."""
    class Args:
        pass

    with tempfile.TemporaryDirectory() as d:
        args = Args()
        args.dir, args.name = d, "REC"
        body = b"body\n"
        with Patched(module, "zero"):
            rc = module.durable_write(args, body, module.seal(body))
        leftovers = sorted(os.listdir(d))
    if rc == 0:
        print("write-publish -> a stalled publication reported success")
        return 1
    if "REC" in leftovers:
        print(f"write-publish -> a stalled publication left a final record: {leftovers}")
        return 1
    if leftovers:
        print(f"write-publish -> a stalled publication left {leftovers}")
        return 1
    print("write-publish -> refused, and nothing was left behind")
    return 0


def case_claim(module):
    """The claim of a run that lost the race it could not see: the state file is already there.

    What must happen is that the claim itself refuses — not the check that preceded it, which by
    construction saw nothing — that the earlier run's state survives byte for byte, and that the
    loser leaves no temporary behind."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "PUBSTATE")
        # The winner's state, distinguishable from what this call would write, so an overwrite
        # cannot hide behind identical bytes.
        held = module.state_record("RUNNING", 2, "claimed-by-the-winner")
        with open(path, "wb") as fh:
            fh.write(held)
        outcome = module.claim_state(path, "RUNNING", 2)
        with open(path, "rb") as fh:
            after = fh.read()
        leftovers = sorted(p for p in os.listdir(d) if p != "PUBSTATE")
    if after != held:
        print("begin-claim -> the state file that was already there was overwritten")
        return 1
    if outcome != "taken":
        print(f"begin-claim -> claiming a directory that is already claimed reported '{outcome}'")
        return 1
    if leftovers:
        print(f"begin-claim -> the losing claim left {leftovers}")
        return 1
    print("begin-claim -> refused, and the earlier state survived untouched")
    return 0


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    delivery, case = argv
    module = load(delivery)
    if case == "short":
        return case_short(module)
    if case == "zero":
        return case_zero(module)
    if case == "publish":
        return case_publish(module)
    if case == "claim":
        return case_claim(module)
    print(f"unknown case '{case}'", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
