#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The S3 atomicity observer: samples one destination, continuously, while somebody else writes.

Every sample is a CONSISTENT SNAPSHOT OF ONE OPEN DESCRIPTOR. The path is opened once, and the
inode, the size and the digest all come from that same descriptor — so a sample can never mix the
inode of one generation of the path with the bytes of another. Sampling the path three times
(stat, stat, hash) does exactly that, and the mixed line it produces is indistinguishable from
the half-written file the check is looking for: it would report a violation where the writer was
atomic, and it could just as easily miss a real one.

A file that is absent at the moment of the sample is recorded as absent, because a destination
that briefly does not exist is itself a violation of an atomic replacement.

    g6-observe-destination.py DEST LOG STOP READY

READY is created once the log is open and sampling is about to begin: the caller waits for it, so
the observer is provably running BEFORE the writer starts. Sampling ends when STOP appears.
"""

import hashlib
import os
import sys


def sample(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return "absent absent absent"
    try:
        st = os.fstat(fd)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        return f"{st.st_ino} {st.st_size} {digest.hexdigest()}"
    except OSError:
        return "unreadable unreadable unreadable"
    finally:
        os.close(fd)


def main(argv):
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    dest, log, stop, ready = argv
    with open(log, "a", buffering=1) as fh:
        # READY means "a sample of the OLD file is already in the log", not "the loop is about to
        # start". Announcing readiness first would let the writer begin between the announcement
        # and the first sample, and the observer would then have no record of the state the
        # destination was in before the replacement — which is half of what it is here to prove.
        fh.write(sample(dest) + "\n")
        with open(ready, "w") as rh:
            rh.write("ready\n")
        while not os.path.exists(stop):
            fh.write(sample(dest) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
