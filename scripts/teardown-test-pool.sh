#!/usr/bin/env bash
# Removes the test pool created by make-test-pool.sh.
#
# Footgun protection (safety-critical): `zpool destroy` runs ONLY if EVERYTHING
# listed below is true:
#   1) the $TP_DIR directory chain has no symlinks and is not writable by others;
#   2) $TP_IMG exists, is a REGULAR file, NOT a symlink (otherwise swapping pool.img ->
#      /dev/null|/dev/sdX would match by canonical path and would destroy the pool);
#   3) the pool's only leaf-vdev == the canonical $TP_IMG, and nothing else.
# Any error/ambiguity → refuse, touch nothing. The backing image is removed
# only after a successful destroy. Config and safety functions — testpool-lib.sh.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testpool-lib.sh
. "$SCRIPT_DIR/testpool-lib.sh"

if ! tp_zpool list "$TP_POOL" >/dev/null 2>&1; then
    echo "Pool '$TP_POOL' not found — nothing to remove."
    echo "(If the image file '$TP_IMG' is left over, check it and remove it manually.)"
    exit 0
fi

# (1) directory chain and (2) image — a regular file, not a symlink — BEFORE destroy.
if ! tp_verify_chain "$TP_DIR"; then
    echo "  Directory chain '$TP_DIR' not confirmed — not running destroy." >&2
    exit 1
fi
if ! tp_require_real_image; then
    echo "  Image not confirmed — not running destroy." >&2
    exit 1
fi
if ! expected="$(tp_expected_vdevs)"; then
    echo "REFUSED: canonicalization of image '$TP_IMG' failed — not running destroy." >&2
    exit 1
fi

# (3) check the FULL topology: the pool's leaf-vdevs == the expected ones (our image, and nothing more).
if ! actual="$(tp_pool_leaf_vdevs "$TP_POOL")"; then
    echo "  Topology of pool '$TP_POOL' not confirmed — doing nothing." >&2
    exit 1
fi

exp_sorted="$(printf '%s\n' "$expected" | sort)"
act_sorted="$(printf '%s\n' "$actual"  | sort)"
if [ "$act_sorted" != "$exp_sorted" ]; then
    echo "REFUSED: the set of leaf-vdevs for pool '$TP_POOL' did not match the harness config —" >&2
    echo "       this may be a production pool, or real devices were added to the pool." >&2
    echo "  expected: $(printf '%s' "$exp_sorted" | tr '\n' '|')" >&2
    echo "  actual: $(printf '%s' "$act_sorted" | tr '\n' '|')" >&2
    echo "  Doing nothing." >&2
    exit 1
fi

if ! tp_zpool destroy "$TP_POOL"; then
    echo "REFUSED: 'zpool destroy $TP_POOL' failed — image NOT removed." >&2
    exit 1
fi
echo "Pool '$TP_POOL' destroyed."

# Removing the backing image: the image is already confirmed as a regular file, the chain
# is verified. A final no-follow recheck as protection against a race.
if [ ! -L "$TP_IMG" ] && [ -f "$TP_IMG" ]; then
    rm -f -- "$TP_IMG" && echo "Image '$TP_IMG' removed."
    rmdir -- "$TP_DIR" 2>/dev/null && echo "Directory '$TP_DIR' removed." || true
else
    echo "Warning: '$TP_IMG' is no longer a regular file — NOT removing." >&2
fi
echo "Done."
