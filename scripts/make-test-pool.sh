#!/usr/bin/env bash
# Creates a file-backed ZFS pool for safe testing of dedcom.
# Run AS ROOT on a Linux host with ZFS. Does not touch production pools.
# Config (env-override) and safety functions live in testpool-lib.sh.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testpool-lib.sh
. "$SCRIPT_DIR/testpool-lib.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run AS ROOT (zpool/zfs privileges are required)." >&2
    exit 1
fi

if tp_zpool list "$TP_POOL" >/dev/null 2>&1; then
    echo "Pool '$TP_POOL' already exists — run teardown-test-pool.sh first" >&2
    exit 1
fi

# Secure directory (0700, ours, not a symlink) + image does not yet exist.
tp_secure_dir || exit 1
tp_assert_image_absent || exit 1

# Directory verified → creating inside it is safe. no-clobber via `set -C`.
( set -C; : > "$TP_IMG" ) || { echo "failed to create '$TP_IMG'" >&2; exit 1; }
truncate -s "$TP_SIZE" "$TP_IMG"

zpool create "$TP_POOL" "$TP_IMG"
zfs create "$TP_POOL/ds_a"
zfs create "$TP_POOL/ds_b"

mkdir -p "/$TP_POOL/ds_a/dup" "/$TP_POOL/ds_b/dup"
head -c 1M /dev/urandom > "/$TP_POOL/ds_a/dup/orig.bin"
cp "/$TP_POOL/ds_a/dup/orig.bin" "/$TP_POOL/ds_a/dup/copy1.bin"   # duplicate within a single dataset
cp "/$TP_POOL/ds_a/dup/orig.bin" "/$TP_POOL/ds_b/dup/copy2.bin"   # duplicate across datasets

# Enough volume so the hashing phase lasts >5 s — needed for the resumability test.
for i in $(seq 1 4000); do
    head -c 64K /dev/urandom > "/$TP_POOL/ds_a/f$i.bin"
done

zfs snapshot "$TP_POOL/ds_a@snap1"   # snapshot -> tests .zfs exclusion

echo "Done. Test pool '$TP_POOL' mounted at /$TP_POOL (image: $TP_IMG)"
echo "  duplicate within a single dataset:   /$TP_POOL/ds_a/dup/{orig,copy1}.bin"
echo "  duplicate across datasets:   /$TP_POOL/ds_a/dup/orig.bin <-> /$TP_POOL/ds_b/dup/copy2.bin"
