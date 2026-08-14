#!/usr/bin/env bash
# Creates a file-backed ZFS pool for safe testing of dedcom.
# Run AS ROOT on a Linux host with ZFS. Does not touch production pools.
#
# SHARED-HOST CONTAINMENT: the backing file, the pool mountpoint and every dataset
# mountpoint live under $DEDCOM_E2E_ROOT and nowhere else. The pool is created with an
# explicit mountpoint and `cachefile=none`, so it never registers itself with the host's
# pool cache and never appears at the filesystem root. Config and safety functions live in
# testpool-lib.sh, which refuses to be sourced without a valid root.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testpool-lib.sh
. "$SCRIPT_DIR/testpool-lib.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run AS ROOT (zpool/zfs privileges are required)." >&2
    exit 1
fi

# Tri-state, and only a PROVED absence permits creation. This check runs before tp_secure_dir,
# before the image and before `zpool create` on purpose: a failed enumeration must not leave a
# half-provisioned directory behind, and «the query broke» is not «the pool is gone».
case "$(tp_pool_presence "$TP_POOL")" in
    present)
        echo "Pool '$TP_POOL' already exists — run teardown-test-pool.sh first" >&2
        exit 1 ;;
    unknown)
        echo "BLOCKED: the pool enumeration failed or was ambiguous — cannot prove '$TP_POOL'" >&2
        echo "         absent, so nothing is created: no directory, no image, no pool." >&2
        exit 1 ;;   # an unproved absence creates nothing
    absent) ;;
esac

# Secure directory (0700, ours, not a symlink, inside the root) + image does not yet exist.
tp_secure_dir || exit 1
tp_assert_image_absent || exit 1
tp_contained "$TP_IMG" || exit 1

# Directory verified → creating inside it is safe. no-clobber via `set -C`.
( set -C; : > "$TP_IMG" ) || { echo "failed to create '$TP_IMG'" >&2; exit 1; }
truncate -s "$TP_SIZE" "$TP_IMG"

# The two options that keep this pool inside the root and out of the host's cache:
#   -m "$TP_MNT"          every dataset inherits a mountpoint under $DEDCOM_E2E_ROOT
#   -o cachefile=none     the host does not record this pool and will not re-import it
zpool create -o cachefile=none -m "$TP_MNT" "$TP_POOL" "$TP_IMG"

zfs create -o mountpoint="$TP_MNT/ds_a" "$TP_POOL/ds_a"
zfs create -o mountpoint="$TP_MNT/ds_b" "$TP_POOL/ds_b"

# Identity, verified the moment it exists rather than assumed at teardown time.
tp_assert_dataset_mounts_contained "$TP_POOL" || {
    echo "REFUSED: a dataset of '$TP_POOL' is mounted outside $TP_MNT" >&2; exit 1; }
tp_manifest_write "$TP_POOL" || { echo "REFUSED: could not record the pool manifest" >&2; exit 1; }
tp_manifest_verify || { echo "REFUSED: the pool does not match the manifest just written" >&2; exit 1; }

mkdir -p "$TP_MNT/ds_a/dup" "$TP_MNT/ds_b/dup"
head -c 1M /dev/urandom > "$TP_MNT/ds_a/dup/orig.bin"
cp "$TP_MNT/ds_a/dup/orig.bin" "$TP_MNT/ds_a/dup/copy1.bin"   # duplicate within a single dataset
cp "$TP_MNT/ds_a/dup/orig.bin" "$TP_MNT/ds_b/dup/copy2.bin"   # duplicate across datasets

# Enough volume so the hashing phase lasts >5 s — needed for the resumability test.
for i in $(seq 1 4000); do
    head -c 64K /dev/urandom > "$TP_MNT/ds_a/f$i.bin"
done

zfs snapshot "$TP_POOL/ds_a@snap1"   # snapshot -> tests .zfs exclusion

echo "Done. Test pool '$TP_POOL' mounted at $TP_MNT (image: $TP_IMG)"
echo "  duplicate within a single dataset:   $TP_MNT/ds_a/dup/{orig,copy1}.bin"
echo "  duplicate across datasets:   $TP_MNT/ds_a/dup/orig.bin <-> $TP_MNT/ds_b/dup/copy2.bin"
echo "  identity manifest: $(tp_manifest_path)"
