#!/usr/bin/env bash
# E2E test: the scan-root guard, including a real bind mount.
#
# SAFETY: everything happens inside ONE disposable fixture created under $DEDCOM_E2E_ROOT, the
# caller's declared containment root. Every mount and umount target is verified to be inside that
# fixture before the call, mounts are undone newest-first and the fixture is removed by an EXIT
# trap. Nothing outside the fixture is ever mounted, unmounted, scanned or deleted -- no
# production path is touched, and without a declared root nothing runs at all.
#
# `mount --bind` needs CAP_SYS_ADMIN. Grant it to a throwaway container only, never host-wide:
#
#   docker run --rm --cap-add SYS_ADMIN \
#     -v "$PWD:/work" -w /work rust:1.95.0 \
#     sh -c 'cargo build --locked --release && bash scripts/e2e-root-guard.sh'
#
# Without that capability the two mount scenarios report SKIP; the path-only scenarios and the
# positive control still run and still have to pass.
#
# Override DEDCOM to point at the binary (default ./target/release/dedcom).
set -euo pipefail

DEDCOM="${DEDCOM:-./target/release/dedcom}"

banner() { printf '\n========== %s ==========\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
skip() { printf 'SKIP: %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

test -x "$DEDCOM" || fail "no dedcom binary at $DEDCOM (set DEDCOM=/path/to/dedcom)"

# SHARED-HOST CONTAINMENT: the fixture is created inside the caller's declared root, never in a
# world-writable spool. A missing root refuses — this script binds and unmounts, and a bind
# whose target was chosen by a default is a bind aimed at somebody else's machine.
E2E_ROOT="${DEDCOM_E2E_ROOT:-}"
[ -n "$E2E_ROOT" ] || fail "DEDCOM_E2E_ROOT is not set — refusing to place a mount fixture by default"
case "$E2E_ROOT" in
/*) ;;
*) fail "DEDCOM_E2E_ROOT='$E2E_ROOT' is not absolute" ;;
esac
[ -d "$E2E_ROOT" ] || fail "DEDCOM_E2E_ROOT='$E2E_ROOT' does not exist"
[ ! -L "$E2E_ROOT" ] || fail "DEDCOM_E2E_ROOT='$E2E_ROOT' is a symbolic link"
E2E_ROOT="$(realpath "$E2E_ROOT")"
case "$E2E_ROOT" in
/ | /home | /tmp | /var/tmp | /var/lib | /root | /run) fail "DEDCOM_E2E_ROOT='$E2E_ROOT' is a system directory" ;;
esac

mkdir -p -m 0700 "$E2E_ROOT/tmp"
FIXTURE="$(mktemp -d "$E2E_ROOT/tmp/dedcom-rootguard-XXXXXX")"
FIXTURE="$(realpath "$FIXTURE")"
case "$FIXTURE" in
"$E2E_ROOT"/*) ;;
*) fail "the fixture must live inside $E2E_ROOT, got $FIXTURE" ;;
esac

MOUNTS=()

# Refuses anything that is not inside the disposable fixture. Used before every mount and umount.
inside_fixture() {
	local target
	target="$(realpath -m "$1")"
	case "$target" in
	"$FIXTURE"/*) return 0 ;;
	*) fail "refusing to touch $target: outside the fixture $FIXTURE" ;;
	esac
}

# Why the last `mount --bind` failed, for an honest SKIP message.
BIND_ERROR=""

# Binds $1 at $2, both inside the fixture. Returns non-zero if the mount failed, WITHOUT recording
# the target or claiming success.
#
# The exit status is tested here rather than left to `set -e`: this function is called as an `if`
# condition, and `errexit` is suppressed for everything inside such a condition. Relying on it meant
# a failed mount carried on to append to MOUNTS, print `bound ...` and return the status of that
# printf, so a container without CAP_SYS_ADMIN ran the scenario unmounted and failed instead of
# skipping.
bind_mount() {
	inside_fixture "$1"
	inside_fixture "$2"
	BIND_ERROR=""
	local output
	if ! output="$(mount --bind "$1" "$2" 2>&1)"; then
		BIND_ERROR="${output:-mount --bind failed with no message}"
		return 1
	fi
	MOUNTS+=("$2")
	printf 'bound %s -> %s\n' "$1" "$2"
}

cleanup() {
	local index target
	for ((index = ${#MOUNTS[@]} - 1; index >= 0; index--)); do
		target="$(realpath -m "${MOUNTS[index]}")"
		case "$target" in
		"$FIXTURE"/*)
			if mountpoint -q "$target"; then
				umount "$target" || printf 'warning: umount %s failed\n' "$target" >&2
			fi
			;;
		*) printf 'warning: not unmounting %s (outside the fixture)\n' "$target" >&2 ;;
		esac
	done
	# The error path obeys the same containment rule as the happy one: a fixture that is not
	# inside the declared root is left alone and reported, never removed on a guess.
	case "$FIXTURE" in
	"$E2E_ROOT"/*) rm -rf "$FIXTURE" ;;
	*) printf 'warning: not removing %s (outside %s)\n' "$FIXTURE" "$E2E_ROOT" >&2 ;;
	esac
}
trap cleanup EXIT

# One scan attempt in its own state directory, so each scenario's checkpoint DB is independent.
# Prints the combined output; returns dedcom's exit status.
scan_roots() {
	local state="$FIXTURE/state-$1"
	shift
	mkdir -p "$state"
	local args=(--state-dir "$state" --no-resume)
	local root
	for root in "$@"; do
		args+=(--scan "$root")
	done
	set +e
	"$DEDCOM" "${args[@]}" 2>&1
	local status=$?
	set -e
	return $status
}

stats_of() {
	"$DEDCOM" --state-dir "$FIXTURE/state-$1" --stats 2>&1
}

# Asserts: the attempt failed, its output names the conflict class, and no session was recorded.
expect_rejected() {
	local label="$1" class="$2"
	shift 2
	local output status
	output="$(scan_roots "$label" "$@")" && status=0 || status=$?
	printf '%s\n' "$output" | sed 's/^/    /'
	[ "$status" -ne 0 ] || fail "$label: the scan was expected to fail, it exited 0"
	printf '%s' "$output" | grep -q "$class" ||
		fail "$label: output does not name the conflict class '$class'"
	local stats
	stats="$(stats_of "$label")"
	printf '%s' "$stats" | grep -q "$FIXTURE" &&
		fail "$label: a scan session was recorded even though the roots were refused"
	pass "$label: refused ($class), no session recorded"
}

banner "fixture"
mkdir -p "$FIXTURE/src/inner" "$FIXTURE/mirror" "$FIXTURE/src/inner_mirror"
# 8 KiB each, byte-identical: headless scanning has no --min-size flag, and the default 4096 would
# filter a smaller pair out of the manifest, leaving the control with nothing to group.
dd if=/dev/zero of="$FIXTURE/src/a.bin" bs=8192 count=1 status=none
cp "$FIXTURE/src/a.bin" "$FIXTURE/src/inner/b.bin"
ln -s "$FIXTURE/src" "$FIXTURE/link"
"$DEDCOM" -V
find "$FIXTURE" -mindepth 1 -maxdepth 2 | sort | sed 's/^/    /'

banner "1. duplicate spelling (no privileges needed)"
expect_rejected dup "duplicate spelling" "$FIXTURE/src" "$FIXTURE/src"

banner "2. nested roots, both orders"
expect_rejected nested "nested roots" "$FIXTURE/src" "$FIXTURE/src/inner"
expect_rejected nested-rev "nested roots" "$FIXTURE/src/inner" "$FIXTURE/src"

banner "3. symlinked root (canonical alias)"
expect_rejected alias "canonical alias" "$FIXTURE/src" "$FIXTURE/link"

banner "4. bind-mounted alias as a selected root"
if bind_mount "$FIXTURE/src" "$FIXTURE/mirror"; then
	expect_rejected bind "same directory object" "$FIXTURE/src" "$FIXTURE/mirror"
	umount "$FIXTURE/mirror"
	MOUNTS=("${MOUNTS[@]:0:${#MOUNTS[@]}-1}")
else
	skip "selected-root bind case not exercised: $BIND_ERROR"
fi

banner "5. bind-mounted alias discovered during the walk"
if bind_mount "$FIXTURE/src" "$FIXTURE/src/inner_mirror"; then
	output="$(scan_roots walk "$FIXTURE/src")" && status=0 || status=$?
	printf '%s\n' "$output" | sed 's/^/    /'
	[ "$status" -ne 0 ] || fail "walk: the scan was expected to fail, it exited 0"
	printf '%s' "$output" | grep -q "same directory" ||
		fail "walk: output does not name the walk-time alias"
	stats_of walk | grep -qE "\[(complete|complete_with_warnings)\]" &&
		fail "walk: a partial scan was published as complete"
	pass "walk: alias found during the walk aborted the scan, nothing published as complete"
	umount "$FIXTURE/src/inner_mirror"
	MOUNTS=("${MOUNTS[@]:0:${#MOUNTS[@]}-1}")
else
	skip "walk-time bind case not exercised: $BIND_ERROR"
fi

banner "6. control: one root over the same tree still scans"
output="$(scan_roots control "$FIXTURE/src")" || fail "control: a disjoint root set must scan"
printf '%s\n' "$output" | sed 's/^/    /'
printf '%s' "$output" | grep -q "Duplicate groups:     1" ||
	fail "control: the two identical files must still form one group"
stats_of control | grep -q "$FIXTURE/src" || fail "control: the session must be recorded"
pass "control: scanned to completion, one group found"

banner "RESULT"
printf 'root-guard E2E: all executed scenarios passed\n'
