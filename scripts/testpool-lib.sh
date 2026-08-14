#!/usr/bin/env bash
# Shared configuration and safety functions of the test-pool harness.
# ONLY for `source` (make-test-pool.sh / teardown-test-pool.sh / tests), not for
# direct execution.
#
# SHARED-HOST CONTAINMENT. This harness is run on machines that are not sandboxes:
# they carry other people's pools, guests and data. Everything it creates therefore
# lives inside ONE caller-supplied root, and every destructive call names one exact
# object that this run itself created. There is no default root, no default owner and
# no prefix-based cleanup: a missing or ambiguous value refuses, it never guesses.
#
# Required environment — absent or malformed is a refusal, not a default:
#   DEDCOM_E2E_ROOT       absolute path; the ONLY tree this harness may write in
#   DEDCOM_E2E_OWNER_UID  numeric uid which, besides root, may own the chain
#
# Optional:
#   DEDCOM_TESTPOOL_NAME  pool name   (default testpool)
#   DEDCOM_TESTPOOL_SIZE  image size  (default 3G)
#
# Fixed layout — nothing is placed outside it:
#   $DEDCOM_E2E_ROOT/pools/<pool>/pool.img      backing file
#   $DEDCOM_E2E_ROOT/pools/<pool>/mount/        pool and dataset mountpoints
#   $DEDCOM_E2E_ROOT/pools/<pool>/manifest.txt  identity captured at create
#   $DEDCOM_E2E_ROOT/state/<scenario>/          checkpoint state directories
#   $DEDCOM_E2E_ROOT/tmp/<scenario>/            temporary files, FIFOs, logs
#   $DEDCOM_E2E_ROOT/evidence/<scenario>/       captures kept after the run
#
# Safety, unchanged from before and still load-bearing:
#   * the whole chain of parents is checked for symlinks and for writability by others;
#   * the image directory MUST be absent and is created by a single `mkdir -m 0700`;
#   * teardown destroys a pool only if its name, GUID, single leaf-vdev and every
#     dataset mountpoint still match the manifest this run wrote at create time.

# --------------------------------------------------------------- fail-closed diagnostics
tp_die() { printf 'REFUSED: %s\n' "$*" >&2; }

# zpool/zfs in the stable C locale — locale-independent output.
tp_zpool() { LC_ALL=C zpool "$@"; }
tp_zfs()   { LC_ALL=C zfs "$@"; }

# --------------------------------------------------------------- path predicates
# Check one existing node: a directory, owner root(0) or the declared owner uid,
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

# Check the ENTIRE chain of parents up to $1 (no-follow): no existing component is a
# symbolic link, and each passes tp_check_node. Closes off path substitution — an outsider
# owns no component and cannot write into one, so creation/deletion cannot be redirected.
# Non-existent components (e.g. a not-yet-created leaf) are skipped.
#
# The owner accepted besides root is TP_OWNER_UID when the environment has been validated,
# and the caller's own euid otherwise (unit tests of this function alone).
tp_verify_chain() {
    local target="$1" uid built="" comp path
    case "$target" in
        /*) ;;
        *) tp_die "path '$target' is not absolute"; return 1;;
    esac
    uid="${TP_OWNER_UID:-$(id -u)}"
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

# Roots this harness refuses outright, whatever else is true about them. Each is either the
# whole machine, a shared spool everyone can write to, or a place where other software already
# keeps state — none of them is a tree one run may claim and later destroy.
tp_root_is_forbidden() {
    local root="$1" home
    home="${HOME:-}"
    case "$root" in
        /|/home|/tmp|/var/tmp|/var/lib|/var|/usr|/etc|/root|/srv|/opt|/mnt|/media|/run)
            return 0;;
    esac
    if [ -n "$home" ] && [ "$root" = "$home" ]; then return 0; fi
    return 1
}

# Validate the containment root and the owner uid, then freeze both. Fail-closed: every
# refusal returns non-zero and sets nothing the caller could go on to use.
tp_require_env() {
    local root uid real

    uid="${DEDCOM_E2E_OWNER_UID-}"
    if [ -z "$uid" ]; then
        tp_die "DEDCOM_E2E_OWNER_UID is not set — this harness never guesses an owner"; return 1
    fi
    case "$uid" in
        ''|*[!0-9]*) tp_die "DEDCOM_E2E_OWNER_UID='$uid' is not a decimal uid"; return 1;;
    esac

    root="${DEDCOM_E2E_ROOT-}"
    if [ -z "$root" ]; then
        tp_die "DEDCOM_E2E_ROOT is not set — this harness has no default root and creates nothing without one"
        return 1
    fi
    case "$root" in
        /*) ;;
        *) tp_die "DEDCOM_E2E_ROOT='$root' is not absolute"; return 1;;
    esac
    case "$root" in
        */) tp_die "DEDCOM_E2E_ROOT='$root' must not end in '/'"; return 1;;
    esac
    case "$root" in
        *//*|*/./*|*/../*|*/.|*/..)
            tp_die "DEDCOM_E2E_ROOT='$root' contains an empty, '.' or '..' component"; return 1;;
    esac
    # Whitespace in the root would survive into every derived path and into the shell words the
    # harness builds from them. Refusing it here is cheaper than quoting perfectly everywhere.
    case "$root" in
        *[$' \t\n']*) tp_die "DEDCOM_E2E_ROOT='$root' contains whitespace"; return 1;;
    esac
    if tp_root_is_forbidden "$root"; then
        tp_die "DEDCOM_E2E_ROOT='$root' is a system or shared directory — refusing to claim it"; return 1
    fi

    # The root itself must exist, must be a real directory and must not be reached through a
    # symlink; realpath must agree with the spelling we were given, so no component can be
    # swapped for a link into somebody else's tree.
    if [ -L "$root" ]; then tp_die "DEDCOM_E2E_ROOT='$root' is a symbolic link"; return 1; fi
    if [ ! -d "$root" ]; then tp_die "DEDCOM_E2E_ROOT='$root' does not exist or is not a directory"; return 1; fi
    if ! real="$(readlink -f -- "$root" 2>/dev/null)"; then
        tp_die "canonicalization of DEDCOM_E2E_ROOT='$root' failed"; return 1
    fi
    if [ "$real" != "$root" ]; then
        tp_die "DEDCOM_E2E_ROOT='$root' canonicalizes to '$real' — refusing an aliased root"; return 1
    fi
    if tp_root_is_forbidden "$real"; then
        tp_die "DEDCOM_E2E_ROOT canonicalizes to the system directory '$real' — refusing"; return 1
    fi

    TP_OWNER_UID="$uid"
    tp_verify_chain "$real" || { tp_die "the chain of '$real' is not trustworthy"; return 1; }

    TP_ROOT="$real"
    return 0
}

# True when $1 lies strictly inside the containment root. Both the spelling and, for paths
# that already exist, the canonical form are checked: a symlink pointing out of the root is
# refused even though its spelling looks contained.
tp_contained() {
    local path="$1" real parent
    case "$path" in
        /*) ;;
        *) tp_die "path '$path' is not absolute"; return 1;;
    esac
    case "$path" in
        *//*|*/./*|*/../*|*/.|*/..)
            tp_die "path '$path' contains an empty, '.' or '..' component"; return 1;;
    esac
    case "$path" in
        "$TP_ROOT"/*) ;;
        *) tp_die "path '$path' is outside the containment root $TP_ROOT"; return 1;;
    esac
    if [ -e "$path" ] || [ -L "$path" ]; then
        if ! real="$(readlink -f -- "$path" 2>/dev/null)"; then
            tp_die "canonicalization of '$path' failed"; return 1
        fi
    else
        # Not created yet: canonicalize the deepest existing ancestor instead, so a symlinked
        # parent cannot be used to place a new object outside the root.
        parent="${path%/*}"
        while [ -n "$parent" ] && [ ! -e "$parent" ]; do parent="${parent%/*}"; done
        [ -n "$parent" ] || parent="/"
        if ! real="$(readlink -f -- "$parent" 2>/dev/null)"; then
            tp_die "canonicalization of the parent of '$path' failed"; return 1
        fi
    fi
    case "$real" in
        "$TP_ROOT"|"$TP_ROOT"/*) return 0 ;;
        *) tp_die "path '$path' resolves to '$real', outside the containment root $TP_ROOT"; return 1 ;;
    esac
}

# ----------------------------------------------------------------- fixed layout
# A scenario label is part of a path, so it is restricted to characters that cannot travel:
# no slash, no dot-run, no whitespace.
tp_check_label() {
    local label="$1"
    case "$label" in
        ''|*/*|*' '*|.|..|*..*) tp_die "invalid scenario/pool label '$label'"; return 1;;
        *[!A-Za-z0-9._-]*) tp_die "invalid character in label '$label'"; return 1;;
    esac
    return 0
}

tp_pool_dir()     { printf '%s/pools/%s\n'    "$TP_ROOT" "$1"; }
tp_state_dir()    { printf '%s/state/%s\n'    "$TP_ROOT" "$1"; }
tp_tmp_dir()      { printf '%s/tmp/%s\n'      "$TP_ROOT" "$1"; }
tp_evidence_dir() { printf '%s/evidence/%s\n' "$TP_ROOT" "$1"; }

# Create one contained working directory (state/tmp/evidence), 0700, refusing anything that
# would land outside the root.
tp_make_dir() {
    local dir="$1"
    tp_contained "$dir" || return 1
    if [ -L "$dir" ]; then tp_die "$dir is a symbolic link"; return 1; fi
    mkdir -p -m 0700 -- "$dir" || { tp_die "failed to create $dir"; return 1; }
    tp_verify_chain "$dir" || return 1
    return 0
}

# --------------------------------------------------------------- image directory
# Safely CREATE the pool directory and its mount point. Fail-closed (return != 0).
# $TP_DIR MUST be absent — it is created with `mkdir -m 0700`; an existing directory is
# NOT accepted and NOT chmod'ed, so an override onto a system path cannot lower its mode.
tp_secure_dir() {
    local dir="$TP_DIR"
    tp_contained "$dir" || return 1
    tp_verify_chain "${dir%/*}" || return 1
    if [ -L "$dir" ] || [ -e "$dir" ]; then
        tp_die "$dir already exists — NOT touching it (run teardown or remove it manually)"; return 1
    fi
    mkdir -p -m 0700 -- "${dir%/*}" || { tp_die "failed to create $(dirname -- "$dir")"; return 1; }
    mkdir -m 0700 -- "$dir" 2>/dev/null || { tp_die "failed to create $dir"; return 1; }
    if [ -L "$dir" ]; then tp_die "$dir — symbolic link"; return 1; fi
    if [ ! -d "$dir" ]; then tp_die "$dir — not a directory"; return 1; fi
    tp_check_node "$dir" "$TP_OWNER_UID" || return 1
    mkdir -m 0700 -- "$TP_MNT" 2>/dev/null || { tp_die "failed to create $TP_MNT"; return 1; }
    tp_contained "$TP_MNT" || return 1
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

# The image MUST exist, be a REGULAR file and NOT a symlink (for teardown, before destroy).
# Closes off substituting pool.img -> /dev/null|/dev/sdX|directory.
tp_require_real_image() {
    if [ -L "$TP_IMG" ]; then tp_die "image '$TP_IMG' — symbolic link, not trusting it"; return 1; fi
    if [ ! -e "$TP_IMG" ]; then tp_die "image '$TP_IMG' does not exist"; return 1; fi
    if [ ! -f "$TP_IMG" ]; then tp_die "image '$TP_IMG' — not a regular file"; return 1; fi
    return 0
}

# The expected single leaf-vdev is the canonical path of the image. Fail-closed: if
# canonicalization failed, returns != 0 (the caller MUST refuse). Call ONLY after
# tp_require_real_image, so the symlink case is already excluded.
tp_expected_vdevs() { readlink -f -- "$TP_IMG"; }

# --------------------------------------------------------------- pool existence, tri-state
# present | absent | unknown — and `unknown` is a verdict, not a shrug. The ONLY source is a
# SUCCESSFUL full enumeration (`zpool list -H -o name`); the name is compared whole-string,
# never as a prefix or pattern. A failed query, or a listing in which the name somehow appears
# more than once, is `unknown` — never `absent`, because "the query broke" and "the pool is
# gone" license opposite actions: the first stops everything, the second permits create or a
# clean noop. Callers case on all three; treating unknown like absent is the fail-open this
# function exists to remove.
tp_pool_presence() {  # pool -> prints present|absent|unknown; always returns 0
    local pool="$1" raw line hits=0
    if ! raw="$(tp_zpool list -H -o name 2>/dev/null)"; then
        printf 'unknown\n'; return 0
    fi
    while IFS= read -r line; do
        [ "$line" = "$pool" ] && hits=$((hits + 1))
    done <<< "$raw"
    case "$hits" in
        0) printf 'absent\n' ;;
        1) printf 'present\n' ;;
        *) printf 'unknown\n' ;;   # one name twice is not a state this harness understands
    esac
    return 0
}

# Remove ONE exact file artifact and prove it gone. rm's exit status alone is not the proof —
# the proof is the absence. Fail-closed: any survival returns non-zero.
tp_remove_file() {  # path -> 0 only when the path is proved absent afterwards
    local path="$1"
    tp_contained "$path" || return 1
    rm -f -- "$path" 2>/dev/null || true
    if [ -e "$path" ] || [ -L "$path" ]; then
        tp_die "'$path' is still present after removal"; return 1
    fi
    return 0
}

# --------------------------------------------------------------- pool identity
# The actual leaf-vdevs of the pool (canonical paths, one per line).
# Returns != 0 on ANY zpool error OR an unexpected structure (fail-closed).
#
# We request the minimal format — the name column (-o name); -v adds vdev rows. IMPORTANT
# (ZFS 2.3+): the detailed vdev rows under -v IGNORE -o name and carry the full set of
# property columns (SIZE ALLOC FREE … HEALTH), whereas the pool summary row stays name-only.
# Therefore the vdev name is taken positionally ($2) and the trailing property columns are
# IGNORED. Safety rests NOT on the number of columns, but on cross-checking the SET of
# leaf-vdevs against our image (below, after awk).
#     zpool list -vHPL -o name <pool>
#   -H = TAB-separator, -P = full paths, -L = resolve symlinks.
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
            # Canonicalization of the actual vdev path is fail-closed: on a readlink error we do
            # NOT substitute the raw path (otherwise it could falsely match the expected one).
            if ! canon="$(readlink -f -- "$p" 2>/dev/null)"; then
                tp_die "canonicalization of the actual vdev path '$p' failed"
                return 1
            fi
            printf '%s\n' "$canon"
        done <<< "$out"
    fi
    return "$rc"
}

# The pool GUID, as a bare decimal string. Fail-closed on any error or on anything that is
# not a single all-digit token: a GUID we could not read is not a GUID we may compare.
tp_pool_guid() {
    local pool="$1" guid
    if ! guid="$(tp_zpool get -H -p -o value guid "$pool" 2>/dev/null)"; then
        tp_die "could not read the GUID of pool '$pool'"; return 1
    fi
    guid="${guid%$'\n'}"
    case "$guid" in
        ''|*[!0-9]*) tp_die "unexpected GUID for pool '$pool': [$guid]"; return 1;;
    esac
    printf '%s\n' "$guid"
    return 0
}

# Every dataset of the pool with its mountpoint, one `<name>\t<mountpoint>` per line, sorted.
# Fail-closed: an error, empty output, or a row that does not belong to this pool refuses.
#
# Validation happens BEFORE the sort and outside any pipeline on purpose: a `return` on the
# upstream side of a pipe only leaves that pipe's subshell, so a refusal there would vanish
# and the function would still exit 0 — a fail-open on the exact query teardown trusts.
tp_pool_dataset_mounts() {
    local pool="$1" raw name mp out=""
    if ! raw="$(tp_zfs list -H -p -r -t filesystem -o name,mountpoint "$pool" 2>/dev/null)"; then
        tp_die "could not list the datasets of pool '$pool'"; return 1
    fi
    [ -n "$raw" ] || { tp_die "empty dataset listing for pool '$pool'"; return 1; }
    while IFS=$'\t' read -r name mp; do
        [ -n "$name" ] || continue
        case "$name" in
            "$pool"|"$pool"/*) ;;
            *) tp_die "dataset '$name' does not belong to pool '$pool'"; return 1;;
        esac
        if [ -z "$mp" ]; then tp_die "dataset '$name' has no mountpoint column"; return 1; fi
        out="${out}${name}"$'\t'"${mp}"$'\n'
    done <<< "$raw"
    printf '%s' "$out" | LC_ALL=C sort
    return 0
}

# Every dataset mountpoint must be inside the containment root. `none` and `legacy` are
# refused too: this harness mounts its datasets where it says it does, and an unmounted or
# legacy dataset is an unverifiable one.
tp_assert_dataset_mounts_contained() {
    local pool="$1" rows line name mp
    rows="$(tp_pool_dataset_mounts "$pool")" || return 1
    while IFS=$'\t' read -r name mp; do
        [ -n "$name" ] || continue
        case "$mp" in
            "$TP_MNT"|"$TP_MNT"/*) ;;
            *) tp_die "dataset '$name' is mounted at '$mp', outside $TP_MNT"; return 1;;
        esac
    done <<< "$rows"
    return 0
}

# --------------------------------------------------------------- identity manifest
# The manifest is written once, at create time, and is the ONLY thing teardown is allowed to
# act on. It names one pool: no prefix, no pattern, no listing.
tp_manifest_path() { printf '%s/manifest.txt\n' "$TP_DIR"; }

tp_manifest_write() {
    local pool="$1" guid vdevs mounts path
    path="$(tp_manifest_path)"
    tp_contained "$path" || return 1
    guid="$(tp_pool_guid "$pool")" || return 1
    vdevs="$(tp_pool_leaf_vdevs "$pool")" || return 1
    mounts="$(tp_pool_dataset_mounts "$pool")" || return 1
    {
        printf 'root\t%s\n' "$TP_ROOT"
        printf 'pool\t%s\n' "$pool"
        printf 'guid\t%s\n' "$guid"
        printf 'image\t%s\n' "$(readlink -f -- "$TP_IMG")"
        printf 'mount\t%s\n' "$TP_MNT"
        printf '%s\n' "$vdevs" | while IFS= read -r v; do [ -n "$v" ] && printf 'vdev\t%s\n' "$v"; done
        printf '%s\n' "$mounts" | while IFS= read -r m; do [ -n "$m" ] && printf 'dataset\t%s\n' "$m"; done
    } > "$path" || { tp_die "failed to write the manifest $path"; return 1; }
    chmod 0600 -- "$path" 2>/dev/null || true
    return 0
}

tp_manifest_field() {  # field -> all values, one per line
    local path
    path="$(tp_manifest_path)"
    [ -r "$path" ] || { tp_die "manifest '$path' is missing or unreadable"; return 1; }
    awk -F'\t' -v f="$1" '$1==f { print substr($0, length($1)+2) }' "$path"
}

# Re-verify, immediately before destroy, that the pool still IS the object this run created.
# Name, GUID, the set of leaf-vdevs and every dataset mountpoint must match the manifest. Any
# mismatch, any query that could not answer, and any mountpoint outside the root refuses —
# BLOCKED, with nothing destroyed.
tp_manifest_verify() {
    local pool m_pool m_guid a_guid m_vdevs a_vdevs m_ds a_ds

    m_pool="$(tp_manifest_field pool)" || return 1
    [ -n "$m_pool" ] || { tp_die "manifest names no pool"; return 1; }
    pool="$m_pool"
    if [ "$pool" != "$TP_POOL" ]; then
        tp_die "manifest names pool '$pool' but this run is configured for '$TP_POOL'"; return 1
    fi

    m_guid="$(tp_manifest_field guid)" || return 1
    a_guid="$(tp_pool_guid "$pool")" || { tp_die "pool GUID unreadable — refusing to destroy"; return 1; }
    if [ "$m_guid" != "$a_guid" ]; then
        tp_die "pool '$pool' now has GUID $a_guid, the manifest recorded $m_guid — this is not our pool"
        return 1
    fi

    m_vdevs="$(tp_manifest_field vdev | LC_ALL=C sort)" || return 1
    a_vdevs="$(tp_pool_leaf_vdevs "$pool" | LC_ALL=C sort)" \
        || { tp_die "pool topology unreadable — refusing to destroy"; return 1; }
    if [ "$m_vdevs" != "$a_vdevs" ]; then
        tp_die "leaf-vdevs of '$pool' changed since create — refusing to destroy"
        printf '  manifest: %s\n' "$(printf '%s' "$m_vdevs" | tr '\n' '|')" >&2
        printf '  actual:   %s\n' "$(printf '%s' "$a_vdevs" | tr '\n' '|')" >&2
        return 1
    fi

    m_ds="$(tp_manifest_field dataset | LC_ALL=C sort)" || return 1
    a_ds="$(tp_pool_dataset_mounts "$pool")" \
        || { tp_die "dataset listing unreadable — refusing to destroy"; return 1; }
    if [ "$m_ds" != "$a_ds" ]; then
        tp_die "dataset set or mountpoints of '$pool' changed since create — refusing to destroy"
        printf '  manifest: %s\n' "$(printf '%s' "$m_ds" | tr '\n' '|')" >&2
        printf '  actual:   %s\n' "$(printf '%s' "$a_ds" | tr '\n' '|')" >&2
        return 1
    fi

    tp_assert_dataset_mounts_contained "$pool" || return 1
    return 0
}

# --------------------------------------------------------------- environment, frozen at source time
# Sourcing this library without a valid containment root is itself a refusal: there is no
# code path in which a caller ends up with a usable default.
tp_require_env || return 1

TP_POOL="${DEDCOM_TESTPOOL_NAME:-testpool}"
tp_check_label "$TP_POOL" || return 1
# shellcheck disable=SC2034  # TP_SIZE is read by make-test-pool.sh
TP_SIZE="${DEDCOM_TESTPOOL_SIZE:-3G}"
TP_DIR="$(tp_pool_dir "$TP_POOL")"
TP_IMG="$TP_DIR/pool.img"
TP_MNT="$TP_DIR/mount"

tp_contained "$TP_DIR" || return 1
