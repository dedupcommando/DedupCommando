#!/usr/bin/env bash
# Removes the test pool created by make-test-pool.sh.
#
# Footgun protection (safety-critical): `zpool destroy` runs ONLY if EVERYTHING listed below
# is true, and the pool it names is read from THIS run's manifest — never from a listing, a
# prefix or a glob:
#   1) the $TP_DIR directory chain has no symlinks, is not writable by others, and lies
#      inside $DEDCOM_E2E_ROOT;
#   2) $TP_IMG exists, is a REGULAR file, NOT a symlink (otherwise swapping pool.img ->
#      /dev/null|/dev/sdX would match by canonical path and would destroy the pool);
#   3) the pool's only leaf-vdev == the canonical $TP_IMG, and nothing else;
#   4) the pool's name and GUID, and the set of datasets with their mountpoints, still match
#      the manifest written at create time, and every mountpoint is inside the root.
# Any error or ambiguity → refuse, touch nothing. The backing image is removed only after a
# successful destroy. Config and safety functions — testpool-lib.sh.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testpool-lib.sh
. "$SCRIPT_DIR/testpool-lib.sh"

# Tri-state, and each state licenses a DIFFERENT action, which is why they must not blur:
#   unknown → BLOCKED. The enumeration failed, so neither «destroy» nor «clean noop» is proved
#             safe; nothing is touched.
#   absent  → a clean noop ONLY when no artifact remains. A leftover directory, image, manifest
#             or mountpoint with no pool to verify against is exactly the state where deleting
#             by path is deleting on faith — BLOCKED, everything left in place.
#   present → the full identity proof below, then destroy, then verified closure.
case "$(tp_pool_presence "$TP_POOL")" in
    unknown)
        echo "BLOCKED: the pool enumeration failed or was ambiguous — cannot decide between" >&2
        echo "         destroy and noop for '$TP_POOL', so NOTHING is removed." >&2
        exit 1 ;;
    absent)
        if [ ! -e "$TP_DIR" ] && [ ! -L "$TP_DIR" ]; then
            echo "Pool '$TP_POOL' is absent and no artifact remains — nothing to do."
            exit 0
        fi
        echo "BLOCKED: pool '$TP_POOL' is absent but artifacts remain — with no pool to verify" >&2
        echo "         them against, nothing is removed. Present right now:" >&2
        for leftover in "$TP_DIR" "$TP_IMG" "$(tp_manifest_path)" "$TP_MNT"; do
            if [ -e "$leftover" ] || [ -L "$leftover" ]; then
                printf '           %s\n' "$leftover" >&2
            fi
        done
        exit 1 ;;   # residue with no pool to verify against stays untouched
    present) ;;
esac

# (1) directory chain and (2) image — a regular file, not a symlink — BEFORE destroy.
if ! tp_contained "$TP_DIR"; then
    echo "  Pool directory '$TP_DIR' is not inside $TP_ROOT — not running destroy." >&2
    exit 1
fi
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

# (4) exact identity: name, GUID, vdev set and every dataset mountpoint, against the manifest
# this run's own create step wrote. A pool that no longer matches it is somebody else's.
if ! tp_manifest_verify; then
    echo "  Identity of pool '$TP_POOL' not confirmed against its manifest — BLOCKED, nothing destroyed." >&2
    exit 1
fi

# The mountpoint list is read from the just-verified manifest BEFORE anything is removed:
# after the destroy these directories should be empty shells, and they are removed by `rmdir`,
# deepest first — never by `rm -rf`, which would also flatten whatever a broken unmount left
# mounted or written there.
MOUNTS_TO_REMOVE="$(tp_manifest_field dataset | cut -f2 | LC_ALL=C sort -r)"

if ! tp_zpool destroy "$TP_POOL"; then
    echo "REFUSED: 'zpool destroy $TP_POOL' failed — image NOT removed." >&2
    exit 1
fi
echo "Pool '$TP_POOL' destroyed."

# Verified closure. Every removal below is checked; nothing is `|| true`d away, and any
# survivor turns the teardown non-zero with the residue listed. Leaving a leftover behind
# REPORTED is recoverable; reporting «Done» over one is how the next run inherits a lie.
leftover_report() {
    echo "BLOCKED: teardown is incomplete — residue under '$TP_DIR':" >&2
    find "$TP_DIR" -mindepth 0 2>/dev/null | sed 's/^/           /' >&2
    exit 1   # an unremoved artifact is a hard failure, never a warning
}

tp_remove_file "$TP_IMG" || leftover_report
echo "Image '$TP_IMG' removed."
tp_remove_file "$(tp_manifest_path)" || leftover_report

while IFS= read -r mp; do
    [ -n "$mp" ] || continue
    tp_contained "$mp" || leftover_report
    if [ -L "$mp" ]; then leftover_report; fi
    if [ -e "$mp" ]; then
        rmdir -- "$mp" 2>/dev/null || leftover_report
    fi
done <<< "$MOUNTS_TO_REMOVE"

if [ -e "$TP_DIR" ] || [ -L "$TP_DIR" ]; then
    rmdir -- "$TP_DIR" 2>/dev/null || leftover_report
fi
if [ -e "$TP_DIR" ] || [ -L "$TP_DIR" ]; then
    leftover_report
fi
echo "Directory '$TP_DIR' fully removed."
echo "Done."
