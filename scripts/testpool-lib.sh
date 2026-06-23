#!/usr/bin/env bash
# Shared configuration and safety functions of the test-pool harness.
# ONLY for `source` (make-test-pool.sh / teardown-test-pool.sh / tests), not for
# direct execution.
#
# Config (overridable via env — set identically for make and teardown):
#   DEDCOM_TESTPOOL_NAME  pool name          (default testpool)
#   DEDCOM_TESTPOOL_DIR   directory for image (default /var/lib/dedcom-testpool)
#   DEDCOM_TESTPOOL_SIZE  image size         (default 3G)
#
# The image is $DIR/pool.img inside its OWN root directory 0700. Safety:
#   * make creates $DIR with a single `mkdir -m 0700` (the directory MUST be absent) —
#     it NEVER chmod's an existing directory (otherwise an override onto /etc etc.
#     would lower the permissions of a system directory);
#   * the entire chain of parents is checked for symlinks and writability by others;
#   * teardown destroys the pool only if its single leaf-vdev is our image,
#     and $TP_IMG MUST be a REGULAR FILE (not a symlink): otherwise substituting
#     pool.img -> /dev/null would match by canonical path and trigger destroy.

# shellcheck disable=SC2034  # TP_POOL is read by the scripts that source this lib
TP_POOL="${DEDCOM_TESTPOOL_NAME:-testpool}"
TP_DIR="${DEDCOM_TESTPOOL_DIR:-/var/lib/dedcom-testpool}"
# shellcheck disable=SC2034  # TP_SIZE is read by make-test-pool.sh
TP_SIZE="${DEDCOM_TESTPOOL_SIZE:-3G}"
TP_IMG="$TP_DIR/pool.img"

# zpool in the stable C locale — locale-independent output.
tp_zpool() { LC_ALL=C zpool "$@"; }

# Unified fail-closed diagnostics.
tp_die() { printf 'REFUSED: %s\n' "$*" >&2; }

# Check one existing node: a directory, owner root(0)/our euid,
# without the write bit for group/other (otherwise an outsider could substitute the component).
tp_check_node() {
    local node="$1" uid="$2" owner mode m
    if [ ! -d "$node" ]; then tp_die "$node — not a directory"; return 1; fi
    owner="$(stat -c '%u' -- "$node" 2>/dev/null)" || { tp_die "stat $node failed"; return 1; }
    mode="$(stat -c '%a' -- "$node" 2>/dev/null)" || { tp_die "stat $node failed"; return 1; }
    if [ "$owner" != "0" ] && [ "$owner" != "$uid" ]; then
        tp_die "$node is owned by uid=$owner (expected root or $uid)"; return 1
    fi
    case "$mode" in *[!0-7]*) tp_die "unexpected mode for $node: $mode"; return 1;; esac
    m=$(( 8#$mode ))
    if [ $(( m & 022 )) -ne 0 ]; then
        tp_die "$node is writable by group/other (mode=$mode)"; return 1
    fi
    return 0
}

# Check the ENTIRE chain of parents up to $1 (no-follow): no existing
# component is a symbolic link, and each passes tp_check_node. Closes off
# path substitution for the root script (an outsider does not own the components and cannot
# write into them → cannot redirect creation/deletion). Non-existent
# components (e.g. a not-yet-created leaf) are skipped.
tp_verify_chain() {
    local target="$1" uid built="" comp path
    case "$target" in
        /*) ;;
        *) tp_die "path '$target' is not absolute"; return 1;;
    esac
    uid="$(id -u)"
    path="${target#/}"
    while [ -n "$path" ]; do
        comp="${path%%/*}"
        path="${path#"$comp"}"; path="${path#/}"
        case "$comp" in ''|'.'|'..') tp_die "suspicious path component in '$target'"; return 1;; esac
        built="$built/$comp"
        if [ -L "$built" ]; then tp_die "symbolic link in the directory chain: $built"; return 1; fi
        if [ -e "$built" ]; then tp_check_node "$built" "$uid" || return 1; fi
    done
    return 0
}

# Safely CREATE the image directory. Fail-closed (return !=0).
# The directory MUST be absent — it is created with a single `mkdir -m 0700` (without -p).
# An existing directory is NOT accepted and NOT chmod'ed (protection against an override onto
# a system path like /etc, /var/lib).
tp_secure_dir() {
    local dir="$TP_DIR" uid
    case "$dir" in /) tp_die "refusing to operate on the root /"; return 1;; esac
    # 1) Check existing ancestors (no-follow, permissions). The leaf — separately below.
    tp_verify_chain "$dir" || return 1
    # 2) The leaf MUST be absent (including not being a symlink/file).
    if [ -L "$dir" ] || [ -e "$dir" ]; then
        tp_die "$dir already exists — NOT touching it (run teardown or delete it manually)"; return 1
    fi
    # 3) Create exactly the leaf with permissions 0700 (without -p: the parent MUST exist).
    mkdir -m 0700 -- "$dir" 2>/dev/null || { tp_die "failed to create $dir (no parent?)"; return 1; }
    # 4) Post-check (without chmod): not a symlink, is a directory, is ours.
    if [ -L "$dir" ]; then tp_die "$dir — symbolic link"; return 1; fi
    if [ ! -d "$dir" ]; then tp_die "$dir — not a directory"; return 1; fi
    uid="$(id -u)"
    tp_check_node "$dir" "$uid" || return 1
    return 0
}

# The image must not exist (including as a symlink) — no-clobber/no-follow (for make).
tp_assert_image_absent() {
    if [ -L "$TP_IMG" ] || [ -e "$TP_IMG" ]; then
        tp_die "image file '$TP_IMG' already exists — run teardown-test-pool.sh first"
        return 1
    fi
    return 0
}

# The image MUST exist, be a REGULAR file and NOT a symlink (for teardown,
# before destroy). Closes off substituting pool.img -> /dev/null|/dev/sdX|directory.
tp_require_real_image() {
    if [ -L "$TP_IMG" ]; then tp_die "image '$TP_IMG' — symbolic link, not trusting it"; return 1; fi
    if [ ! -e "$TP_IMG" ]; then tp_die "image '$TP_IMG' does not exist"; return 1; fi
    if [ ! -f "$TP_IMG" ]; then tp_die "image '$TP_IMG' — not a regular file"; return 1; fi
    return 0
}

# The expected single leaf-vdev is the canonical path of the image. Fail-closed:
# if canonicalization failed, returns !=0 (the caller MUST refuse).
# Call ONLY after tp_require_real_image (then the symlink is already excluded and
# readlink will not lead to someone else's target).
tp_expected_vdevs() { readlink -f -- "$TP_IMG"; }

# The actual leaf-vdevs of the pool (canonical paths, one per line).
# Returns !=0 on ANY zpool error OR an unexpected structure (fail-closed).
#
# We request the minimal format — the name column (-o name); -v adds vdev
# rows. IMPORTANT (ZFS 2.3+): the detailed vdev rows under -v IGNORE -o name and
# carry the full set of property columns (SIZE ALLOC FREE … HEALTH), whereas the
# pool summary row stays name-only. Therefore the vdev name is taken positionally ($2), and
# the trailing property columns are IGNORED. Safety rests NOT on the number of columns,
# but on cross-checking the SET of leaf-vdevs against our image (below, after awk).
#     zpool list -vHPL -o name <pool>
#   -H = TAB-separator, -P = full paths, -L = resolve symlinks.
# Parsing by field boundaries (-F'\t'):
#   - pool row     : no leading tab, name == $1 (we expect EXACTLY the pool name);
#   - vdev row     : leading tab, name == $2, then — property columns (ignored);
#   - containers (mirror-/raidz-/…) and sections (logs/cache/…) → refuse;
#   - the name MUST be an absolute path;
#   - a row without a leading tab (other than the summary) → refuse.
tp_pool_leaf_vdevs() {
    local pool="$1" raw out rc=0
    if ! raw="$(tp_zpool list -vHPL -o name "$pool" 2>/dev/null)"; then
        tp_die "'zpool list -vHPL -o name $pool' exited with an error"; return 1
    fi
    [ -n "$raw" ] || { tp_die "empty output of 'zpool list' for $pool"; return 1; }
    out="$(awk -F'\t' -v pool="$pool" '
        function trim(s){ gsub(/^[ \t]+|[ \t]+$/,"",s); return s }
        NR==1 {
            if ($0 ~ /^\t/) { print "REFUSED: first row has a leading tab" > "/dev/stderr"; exit 3 }
            if (NF != 1) { printf("REFUSED: pool summary — extra fields (expected 1 column -o name): [%s]\n", $0) > "/dev/stderr"; exit 4 }
            if (trim($1) != pool) { printf("REFUSED: pool summary «%s», expected «%s»\n", trim($1), pool) > "/dev/stderr"; exit 3 }
            next
        }
        $0 ~ /^\t/ {
            # ZFS 2.3+ under -v adds property columns after the name even with -o name:
            # the name is $2, the trailing fields are ignored (see the function header). We require
            # only that the name field is present.
            if (NF < 2) { printf("REFUSED: vdev row without a name field: [%s]\n", $0) > "/dev/stderr"; exit 4 }
            name = trim($2)
            if (name == "") { print "REFUSED: empty vdev name" > "/dev/stderr"; exit 2 }
            if (name ~ /^(mirror|raidz[0-9]*|draid[0-9]*|spare|replacing|log|dedup|special|indirect)-[0-9]+$/) {
                printf("REFUSED: container vdev «%s» — harness has no containers\n", name) > "/dev/stderr"; exit 6
            }
            if (substr(name, 1, 1) != "/") {
                printf("REFUSED: vdev name «%s» — not an absolute path\n", name) > "/dev/stderr"; exit 7
            }
            print name; leaves++
            next
        }
        {
            w = trim($1); sub(/[ \t].*$/, "", w)
            if (w=="logs"||w=="cache"||w=="spare"||w=="dedup"||w=="special") {
                printf("REFUSED: pool %s contains a «%s» section (additional devices)\n", pool, w) > "/dev/stderr"; exit 6
            }
            printf("REFUSED: unexpected row without a leading tab: [%s]\n", $0) > "/dev/stderr"; exit 5
        }
        END { if (leaves == 0) { print "REFUSED: no leaf-vdev found" > "/dev/stderr"; exit 8 } }
    ' <<< "$raw")" || rc=$?
    if [ "$rc" -eq 0 ]; then
        local p canon
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            # Canonicalization of the actual vdev path is fail-closed: on a readlink error
            # we do NOT substitute the raw path (otherwise it could falsely match the expected one).
            if ! canon="$(readlink -f -- "$p" 2>/dev/null)"; then
                tp_die "canonicalization of the actual vdev path '$p' failed"
                return 1
            fi
            printf '%s\n' "$canon"
        done <<< "$out"
    fi
    return "$rc"
}
