#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The matcher is what every other G6 proof leans on: the mutation oracle decides KILLED versus
# SURVIVED by asking whether a refusal names its cause. If that question can answer "no" to a
# text that plainly contains the cause, then a surviving mutant is recorded as killed at random,
# and the whole matrix is decoration.
#
# `producer | grep -q needle` is exactly that kind of question. grep exits at the first match,
# the producer is still writing, the kernel sends it SIGPIPE, and `set -o pipefail` reports the
# producer's 141 as the pipeline's status. A match is read as a miss. It is not rare and it is
# not a flake to be re-run: it is what the pipeline does whenever the text is longer than a pipe
# buffer, which the G6 refusals routinely are.
#
# This suite proves three things on ONE unchanged input, 400 times each:
#   1. the old pipeline form really does lose            (red evidence, not a story)
#   2. g6_has never loses                                (400/400)
#   3. g6_has_line matches whole lines and nothing else
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-g6-stubs.sh
. "$HERE/test-g6-stubs.sh"

ROUNDS="${G6_MATCHER_ROUNDS:-400}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }

# A haystack bigger than a pipe buffer (64 KiB on Linux) with the needle at the very front:
# the shape that makes the pipeline lose every time rather than once in a while.
NEEDLE='the refusal names the cell it refuses over'
pad='----------------'
while [ "${#pad}" -lt 262144 ]; do pad="$pad$pad"; done
HAY="$NEEDLE
$pad
a second line that ends the text"

printf 'haystack %s bytes, needle at offset 0, %s rounds\n\n' "${#HAY}" "$ROUNDS"

# --- 1. the old form, kept here as evidence and nowhere else in the tree --------------------
lost=0
for _ in $(seq 1 "$ROUNDS"); do
  printf '%s' "$HAY" | grep -qF -- "$NEEDLE" || lost=$((lost+1))
done
if [ "$lost" -gt 0 ]; then
  ok "the old pipeline form loses a present match ($lost/$ROUNDS said no)"
else
  bad "the old pipeline form did not lose here — the proof needs a bigger haystack, not a pass"
fi

# --- 2. the matcher that reads its whole input ----------------------------------------------
missed=0
for _ in $(seq 1 "$ROUNDS"); do
  g6_has "$HAY" "$NEEDLE" || missed=$((missed+1))
done
[ "$missed" = 0 ] && ok "g6_has found it $ROUNDS/$ROUNDS" \
                  || bad "g6_has missed $missed of $ROUNDS"

# The other direction: an absent needle must never be reported present, also 400 times.
false_hits=0
for _ in $(seq 1 "$ROUNDS"); do
  g6_has "$HAY" 'a cause nobody printed' && false_hits=$((false_hits+1))
done
[ "$false_hits" = 0 ] && ok "g6_has reported no false hit in $ROUNDS rounds" \
                      || bad "g6_has reported $false_hits false hits"

# --- 3. whole-line semantics -----------------------------------------------------------------
LINES='VERDICT	BLOCKED
prefix VERDICT	PASS suffix
	VERDICT	FAIL'
g6_has_line "$LINES" 'VERDICT	BLOCKED' \
  && ok "g6_has_line matches a whole line" || bad "g6_has_line matches a whole line"
g6_has_line "$LINES" 'VERDICT	PASS' \
  && bad "g6_has_line must not match inside a longer line" \
  || ok "g6_has_line does not match inside a longer line"
g6_has_line "$LINES" 'VERDICT	FAIL' \
  && bad "g6_has_line must not ignore leading whitespace" \
  || ok "g6_has_line does not ignore leading whitespace"
g6_has_line "$LINES" '	VERDICT	FAIL' \
  && ok "g6_has_line matches a line that begins with a tab" \
  || bad "g6_has_line matches a line that begins with a tab"

# A needle carrying glob metacharacters is data, not a pattern: `case` would treat an unquoted
# expansion as one, and a refusal quoting a path with a bracket would then match anything.
g6_has 'the target [a-z] was refused' '[a-z]' \
  && ok "a needle with glob metacharacters is matched literally" \
  || bad "a needle with glob metacharacters is matched literally"
g6_has 'the target q was refused' '[a-z]' \
  && bad "a needle with glob metacharacters must not be expanded" \
  || ok "a needle with glob metacharacters is not expanded"

printf '\n== result: PASS=%d FAIL=%d over %d rounds each ==\n' "$PASS" "$FAIL" "$ROUNDS"
[ "$FAIL" = 0 ]
