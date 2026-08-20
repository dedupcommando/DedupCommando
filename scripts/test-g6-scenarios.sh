#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Directed failure scenarios for the G6 delivery. Sourced, never run.
#
# One place, two readers. `test-g6-failures.sh` runs every scenario against the pristine delivery
# and asserts that the guard it aims at actually holds; `test-g6-mutations.sh` runs the SAME
# function against a delivery with exactly that guard removed. Keeping the scenario and its
# expected cause in one registry is what makes the pair one-to-one: a cause that is edited in the
# suite but not in the matrix cannot silently stop meaning anything.
#
# Each row declares its polarity, which says what the two copies are expected to do:
#
#   refuse   the pristine REFUSES and names the cause; the mutant accepts (exit 0)
#   hold     the pristine PASSES the scenario (exit 0); the mutant fails and names the cause
#   reclass  BOTH fail, each with the exit status the row declares; the pristine names the cause
#            and the mutant names something else. This is for guards that decide WHICH refusal
#            happens rather than whether one does.
#
# A scenario never asserts through a marker the code writes about itself when the fact is
# observable directly: fail-fast is proved by which steps left evidence of running, not by the
# step name the run recorded; provenance is proved against the checkpoint and the sanction, not
# by the presence of a receipt.
#
# The caller provides: $WORK (a scratch dir), the stub bench from test-g6-stubs.sh, and $DEDCOM.

# ------------------------------------------------------------------ bench

export G6T_G=40 G6T_U=20

g6s_require_bin() {
  [ -x "${DEDCOM:-/nonexistent}" ] \
    || { echo "ABORT: set DEDCOM to the built candidate" >&2; exit 1; }
}

g6s_world() { g6t_new_world "$WORK" >/dev/null; }

g6s_seal() {  # delivery candidate
  local d="$1" bin="$2" bsha
  CAL="$G6T_W/cal.txt"; SANC="$G6T_W/sanc.txt"; PLAN="$G6T_W/plan.txt"
  g6t_write_calibration rehearsal "$CAL"
  g6t_write_plan "$PLAN"
  bsha="$(bash "$d/g6-controller.sh" bundle | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')"
  g6t_write_sanction rehearsal "$SANC" "$CAL" "$bin" "$bsha" "$PLAN"
  export G6_CALIBRATION="$CAL" G6_SANCTION="$SANC" G6_RESOURCE_PLAN="$PLAN"
  export G6_BIN="$bin" G6_NOW=5000 G6_CONTOUR=local
}

g6s_sealed_world() { g6s_world; g6s_seal "$1" "${2:-$DEDCOM}"; }

g6s_route()   { bash "$1/g6-controller.sh" route --mode "${2:-rehearsal}"; }
g6s_ctl()     { local d="$1"; shift; bash "$d/g6-controller.sh" "$@"; }
g6s_lib()     { local d="$1"; shift; bash "$d/g6-image-lib.sh" "$@"; }

# How many times a stubbed privileged tool was invoked in this world.
g6s_calls() { grep -c "^$1 " "$G6T_LOG" 2>/dev/null || true; }

# How many times a device was ATTACHED. `losetup --list` is a question, not an attachment, and
# counting every losetup line would count the questions the chain asks on every step.
g6s_attach_calls() { grep -c "^losetup /dev/" "$G6T_LOG" 2>/dev/null || true; }

g6s_terminal_field() { awk -F'\t' -v k="$1" '$1 == k { print $2 }' "$G6_WORK/TERMINAL" 2>/dev/null; }

# The state word a delivery reports for a state file.
g6s_state_word() {  # delivery state-file
  "$1/g6-publish-record.py" --query-state --state-file "$2" 2>&1 \
    | awk -F'\t' '$1 == "STATE" { print $2 }'
}

# The RECORD status a delivery reports for a published record behind a state file.
g6s_record_status() {  # delivery state-file dir
  "$1/g6-publish-record.py" --query-state --state-file "$2" --dir "$3" 2>&1 \
    | awk -F'\t' '$1 == "RECORD" { print $2 }'
}

# --- stand-in candidates ------------------------------------------------------
#
# Stand-ins wrap the real candidate. They exist so a scenario can put the DESTINATION into a
# state the real product never produces, which is the only way to find out whether the harness
# would have noticed.

# Records every invocation, so "nothing ran" can be proved instead of assumed. It wraps whatever
# it is given, so a stand-in can be made observable without a second copy of it.
g6s_logging_candidate() {  # out log [inner]
  { printf '#!/usr/bin/env bash\n'
    printf 'printf "%%s\\n" "$*" >> %q\n' "$2"
    printf 'exec %q "$@"\n' "${3:-$DEDCOM}"
  } > "$1"
  chmod +x "$1"
}

# Exports NON-atomically on the Nth export: it produces the right bytes, then truncates the
# destination and rewrites it in place after a pause. Anyone sampling the destination during the
# pause sees a file that is neither the old one nor the new one — which is the entire content of
# the S3 postcondition, and is invisible to a check that only compares the endpoints.
g6s_partial_writer() {  # out counter-file nth
  { printf '#!/usr/bin/env bash\n'
    printf 'dest=""; prev=""\n'
    printf 'for a in "$@"; do [ "$prev" = --export-csv ] && dest="$a"; prev="$a"; done\n'
    printf '[ -n "$dest" ] || exec %q "$@"\n' "$DEDCOM"
    printf 'n=$(( $(cat %q 2>/dev/null || echo 0) + 1 )); printf "%%s\\n" "$n" > %q\n' "$2" "$2"
    printf '[ "$n" = %q ] || exec %q "$@"\n' "$3" "$DEDCOM"
    printf '%q "$@" || exit $?\n' "$DEDCOM"
    printf 'cp -- "$dest" "$dest.standin"\n'
    printf ': > "$dest"\n'
    printf 'sleep 1\n'
    printf 'cat -- "$dest.standin" > "$dest"\n'
    printf 'rm -f -- "$dest.standin"\n'
    printf 'exit 0\n'
  } > "$1"
  chmod +x "$1"
}

# Scans correctly and then removes one product table from the checkpoint it just wrote. The
# stamp survives, the schema does not.
g6s_schema_dropper() {  # out table
  local dropper="$1.drop.py"
  { printf 'import sqlite3, sys\n'
    printf 'c = sqlite3.connect(sys.argv[1])\n'
    printf 'c.execute("DROP TABLE %s")\n' "$2"
    printf 'c.commit()\n'
  } > "$dropper"
  { printf '#!/usr/bin/env bash\n'
    printf 'sd=""; prev=""; scanning=0\n'
    printf 'for a in "$@"; do\n'
    printf '  [ "$prev" = --state-dir ] && sd="$a"\n'
    printf '  [ "$a" = --scan ] && scanning=1\n'
    printf '  prev="$a"\n'
    printf 'done\n'
    printf '%q "$@" || exit $?\n' "$DEDCOM"
    printf '[ "$scanning" = 1 ] && python3 %q "$sd/dedcom.db"\n' "$dropper"
    printf 'exit 0\n'
  } > "$1"
  chmod +x "$1"
}

# Scans correctly and then removes one row from the checkpoint, so what the product reports no
# longer follows from the parameters the fixture was built with. The counts contradict the
# derived formulas without anything about the environment being wrong — which is the difference
# between FAIL and BLOCKED.
g6s_row_deleter() {  # out
  local edit="$1.delete.py"
  { printf 'import sqlite3, sys\n'
    printf 'c = sqlite3.connect(sys.argv[1])\n'
    printf 'c.execute("DELETE FROM file WHERE rowid = (SELECT MIN(rowid) FROM file)")\n'
    printf 'c.commit()\n'
  } > "$edit"
  { printf '#!/usr/bin/env bash\n'
    printf 'sd=""; prev=""; scanning=0\n'
    printf 'for a in "$@"; do\n'
    printf '  [ "$prev" = --state-dir ] && sd="$a"\n'
    printf '  [ "$a" = --scan ] && scanning=1\n'
    printf '  prev="$a"\n'
    printf 'done\n'
    printf '%q "$@" || exit $?\n' "$DEDCOM"
    printf '[ "$scanning" = 1 ] && python3 %q "$sd/dedcom.db"\n' "$edit"
    printf 'exit 0\n'
  } > "$1"
  chmod +x "$1"
}

# Scans correctly and then edits ITSELF, so the binary that produced the checkpoint is no longer
# the binary the sanction pinned by the time the receipt is written.
g6s_self_editing_candidate() {  # out
  { printf '#!/usr/bin/env bash\n'
    printf 'rc=0; %q "$@" || rc=$?\n' "$DEDCOM"
    printf 'for a in "$@"; do\n'
    printf '  [ "$a" = --scan ] && printf "# the binary changed under the run\\n" >> "$0"\n'
    printf 'done\n'
    printf 'exit $rc\n'
  } > "$1"
  chmod +x "$1"
}

# Takes its time over the scan, so a signal can be delivered while the route is demonstrably in
# the middle of something rather than in whatever state a race happened to leave it.
g6s_slow_candidate() {  # out seconds
  { printf '#!/usr/bin/env bash\n'
    printf 'for a in "$@"; do [ "$a" = --scan ] && sleep %q; done\n' "$2"
    printf 'exec %q "$@"\n' "$DEDCOM"
  } > "$1"
  chmod +x "$1"
}

# Scans correctly and then drops one INDEX. The stamp is intact, every table is present, every
# column is where it should be — and the schema is still not the one the product creates.
g6s_column_dropper() {  # out table column
  # The same shape as the index dropper: the stand-in runs the real candidate and then removes
  # ONE element of the schema, so the refusal that follows is about that element and nothing
  # else. A guard nobody can take away is a guard nobody has proved.
  local edit="$1.column.py"
  { printf 'import sqlite3, sys
'
    printf 'c = sqlite3.connect(sys.argv[1])
'
    printf 'c.execute("ALTER TABLE %s DROP COLUMN %s")
' "$2" "$3"
    printf 'c.commit()
'
  } > "$edit"
  { printf '#!/usr/bin/env bash
'
    printf 'sd=""; prev=""; scanning=0
'
    printf 'for a in "$@"; do
'
    printf '  [ "$prev" = --state-dir ] && sd="$a"
'
    printf '  [ "$a" = --scan ] && scanning=1
'
    printf '  prev="$a"
'
    printf 'done
'
    printf '%q "$@" || exit $?
' "$DEDCOM"
    printf '[ "$scanning" = 1 ] && python3 %q "$sd/dedcom.db"
' "$edit"
    printf 'exit 0
'
  } > "$1"
  chmod +x "$1"
}

g6s_index_dropper() {  # out index
  local edit="$1.index.py"
  { printf 'import sqlite3, sys\n'
    printf 'c = sqlite3.connect(sys.argv[1])\n'
    printf 'c.execute("DROP INDEX %s")\n' "$2"
    printf 'c.commit()\n'
  } > "$edit"
  { printf '#!/usr/bin/env bash\n'
    printf 'sd=""; prev=""; scanning=0\n'
    printf 'for a in "$@"; do\n'
    printf '  [ "$prev" = --state-dir ] && sd="$a"\n'
    printf '  [ "$a" = --scan ] && scanning=1\n'
    printf '  prev="$a"\n'
    printf 'done\n'
    printf '%q "$@" || exit $?\n' "$DEDCOM"
    printf '[ "$scanning" = 1 ] && python3 %q "$sd/dedcom.db"\n' "$edit"
    printf 'exit 0\n'
  } > "$1"
  chmod +x "$1"
}

# Scans correctly and then rebuilds one index with the same NAME over fewer columns. Nothing is
# missing by name; the index is simply not the index it says it is.
g6s_index_reshaper() {  # out index table columns
  local edit="$1.reshape.py"
  { printf 'import sqlite3, sys\n'
    printf 'c = sqlite3.connect(sys.argv[1])\n'
    printf 'c.execute("DROP INDEX %s")\n' "$2"
    printf 'c.execute("CREATE INDEX %s ON %s(%s)")\n' "$2" "$3" "$4"
    printf 'c.commit()\n'
  } > "$edit"
  g6s_after_scan_edit "$1" "$edit"
}

# Scans correctly and then drops a column from a table this verifier never queries.
g6s_column_dropper() {  # out table column
  local edit="$1.column.py"
  { printf 'import sqlite3, sys\n'
    printf 'c = sqlite3.connect(sys.argv[1])\n'
    printf 'c.execute("ALTER TABLE %s DROP COLUMN %s")\n' "$2" "$3"
    printf 'c.commit()\n'
  } > "$edit"
  g6s_after_scan_edit "$1" "$edit"
}

# The wrapper the checkpoint-editing stand-ins share: scan for real, then run one edit against
# the checkpoint that was just written.
g6s_after_scan_edit() {  # out edit-script
  { printf '#!/usr/bin/env bash\n'
    printf 'sd=""; prev=""; scanning=0\n'
    printf 'for a in "$@"; do\n'
    printf '  [ "$prev" = --state-dir ] && sd="$a"\n'
    printf '  [ "$a" = --scan ] && scanning=1\n'
    printf '  prev="$a"\n'
    printf 'done\n'
    printf '%q "$@" || exit $?\n' "$DEDCOM"
    printf '[ "$scanning" = 1 ] && python3 %q "$sd/dedcom.db"\n' "$2"
    printf 'exit 0\n'
  } > "$1"
  chmod +x "$1"
}

# Scans correctly and then appends a line to the invocation record the controller published
# before it started. Nothing about the scan is wrong; what is wrong is the record the receipt is
# about to be built out of, and the corruption happens where a real one would — during the run,
# after the record was written and before anything read it back.
g6s_invocation_tamperer() {  # out invocation-path
  { printf '#!/usr/bin/env bash\n'
    printf 'rc=0; %q "$@" || rc=$?\n' "$DEDCOM"
    printf 'for a in "$@"; do\n'
    printf '  [ "$a" = --scan ] && printf "tampered\\twith\\n" >> %q\n' "$2"
    printf 'done\n'
    printf 'exit $rc\n'
  } > "$1"
  chmod +x "$1"
}

# Reports a workload that the checkpoint does not carry, so the S1 postcondition is contradicted
# by the candidate's own answer while everything else about the run is ordinary.
g6s_badstats_candidate() {  # out
  { printf '#!/usr/bin/env bash\n'
    printf 'for a in "$@"; do\n'
    printf '  if [ "$a" = --stats ]; then %q "$@" | sed "s/files=[0-9]*/files=999999/"; exit 0; fi\n' \
      "$DEDCOM"
    printf 'done\n'
    printf 'exec %q "$@"\n' "$DEDCOM"
  } > "$1"
  chmod +x "$1"
}

# ------------------------------------------------------------------ publisher

# A record whose body was cut short while its seal lines landed. The digest matches the bytes
# that are there, so only the recorded SIZE says a longer body was written — exactly the shape a
# partial write leaves behind when the tail reaches the disk and the middle does not.
g6s_pub_partial_write() {  # delivery
  local d="$1" p="$WORK/pw$RANDOM"; mkdir -p "$p"
  local body='field	value
'
  { printf '%s' "$body"
    printf 'record-size\t%s\n' "$(( ${#body} + 4096 ))"
    printf 'record-sha256\t%s\n' "$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)"
  } > "$p/REC"
  "$d/g6-publish-record.py" --verify --dir "$p" --name REC 2>&1
}

g6s_pub_zero_write() {  # delivery
  local d="$1" p="$WORK/zw$RANDOM"; mkdir -p "$p"
  printf '' | "$d/g6-publish-record.py" --dir "$p" --name REC 2>&1
}

# A state file with a third line. The seal over the head is perfectly good; the SHAPE is not, and
# a state file nobody can account for in full is not a state file.
g6s_pub_state_corrupt() {  # delivery
  local d="$1" p="$WORK/sc$RANDOM"; mkdir -p "$p"
  # The head carries its full five fields and seals correctly, so the SHAPE is the only thing
  # left to object to. A short head would be caught by the field count as well, and the row
  # could not tell which of the two guards refused.
  local head='PUBLISHED 0 TERMINAL 512 abc'
  { printf '%s\n' "$head"
    printf 'state-sha256\t%s\n' "$(printf '%s\n' "$head" | sha256sum | cut -d' ' -f1)"
    printf 'and something else\n'
  } > "$p/PUBSTATE"
  local observed
  observed="$(g6s_state_word "$d" "$p/PUBSTATE")"
  [ "$observed" = FAILED ] \
    || { printf 'state-corrupt -> the state reads %s, not FAILED\n' "$observed"; return 1; }
  return 0
}

# Unreadable, and unreadable to root as well: a directory where a file is expected. Permissions
# would prove nothing in a container that runs as root.
g6s_pub_state_unreadable() {  # delivery
  local d="$1" p="$WORK/su$RANDOM"; mkdir -p "$p/PUBSTATE"
  local observed
  observed="$(g6s_state_word "$d" "$p/PUBSTATE")"
  [ "$observed" = FAILED ] \
    || { printf 'state-unreadable -> the state reads %s, not FAILED\n' "$observed"; return 1; }
  return 0
}

# A properly sealed state carrying a word nobody defined. Unknown is not empty, and it is
# certainly not NOT_STARTED.
g6s_pub_state_unknown() {  # delivery
  local d="$1" p="$WORK/sk$RANDOM"; mkdir -p "$p"
  # Five fields, sealed, and the only thing wrong with it is the word. Anything shorter would be
  # refused by the field count first and this row would be about that guard instead.
  local head='FINISHED 0 TERMINAL 512 abc'
  { printf '%s\n' "$head"
    printf 'state-sha256\t%s\n' "$(printf '%s\n' "$head" | sha256sum | cut -d' ' -f1)"
  } > "$p/PUBSTATE"
  local observed
  observed="$(g6s_state_word "$d" "$p/PUBSTATE")"
  [ "$observed" = FAILED ] \
    || { printf 'state-unknown -> the state reads %s, not FAILED\n' "$observed"; return 1; }
  return 0
}

g6s_pub_terminal_deleted() {  # delivery
  local d="$1"; g6s_sealed_world "$d"
  g6s_route "$d" >/dev/null 2>&1
  rm -f "$G6_WORK/TERMINAL"
  g6s_route "$d" 2>&1
}

# A record of somebody else's, sealed exactly as ours are. It verifies against its own seal, and
# the only thing that knows it is the wrong record is the digest the state file recorded.
g6s_pub_terminal_substituted() {  # delivery
  local d="$1"; g6s_sealed_world "$d"
  g6s_route "$d" >/dev/null 2>&1
  rm -f "$G6_WORK/TERMINAL"
  printf 'verdict\tPASS\ncode\t0\nreason\tsomebody elses run\n' \
    | "$d/g6-publish-record.py" --dir "$G6_WORK" --name TERMINAL >/dev/null 2>&1
  g6s_route "$d" 2>&1
}

# Re-entry, for each of the three outcomes. What is asserted is the same in all three: the stored
# code survives, the second attempt refuses with code 2, and NOTHING was run — no candidate
# invocation, no second scan. The three differ in which outcome the first run reached.
g6s_reentry() {  # delivery break-how tag want-code
  local d="$1" how="$2" tag="$3" want="$4" clog rc=0 state code inner=""
  g6s_world
  clog="$G6T_W/candidate.log"; : > "$clog"
  # A FAIL has to be earned by the candidate producing a wrong answer. Moving the scale in the
  # sanction moves it for the generator AND the verifier, so it contradicts nothing at all.
  if [ "$how" = fail ]; then
    g6s_row_deleter "$G6T_W/deleter"; inner="$G6T_W/deleter"
  fi
  g6s_logging_candidate "$G6T_W/candidate" "$clog" "$inner"
  g6s_seal "$d" "$G6T_W/candidate"
  case "$how" in
    # A BLOCKED that leaves a record has to happen AFTER the run announces itself. Closing the
    # sanction window used to do it, but that is a read-only check and since C2-2 it refuses
    # before BEGIN, writing nothing — there would be no first run to re-enter. Starving the
    # filesystem inside the image blocks between batches, which is post-BEGIN and terminalizes.
    blocked) export G6T_DF_STARVE_AFTER=0 ;;
  esac
  g6s_route "$d" >/dev/null 2>&1 || true
  code="$(g6s_terminal_field code)"
  [ "$code" = "$want" ] || { printf '%s -> the first run ended %s, not %s\n' "$tag" "$code" "$want"
                             return 1; }
  : > "$clog"
  g6s_route "$d" >/dev/null 2>&1 || rc=$?
  [ "$rc" = 2 ] || { printf '%s -> re-entry exited %s, not 2\n' "$tag" "$rc"; return 1; }
  [ ! -s "$clog" ] || { printf '%s -> the candidate ran on re-entry: %s\n' "$tag" "$(head -1 "$clog")"
                        return 1; }
  state="$("$d/g6-publish-record.py" --query-state --state-file "$G6_WORK/PUBSTATE" 2>&1 \
            | awk -F'\t' '$1 == "STATE" { print $2, $3 }')"
  [ "$state" = "PUBLISHED $want" ] \
    || { printf '%s -> the state reports %s, not PUBLISHED %s\n' "$tag" "$state" "$want"; return 1; }
  return 0
}

g6s_pub_reentry_pass()    { g6s_reentry "$1" pass    reentry-0 0; }
g6s_pub_reentry_fail()    { g6s_reentry "$1" fail    reentry-1 1; }
g6s_pub_reentry_blocked() { g6s_reentry "$1" blocked reentry-2 2; }

# ------------------------------------------------------------------ S3

# The stand-in writer holds a half-written destination for a second. Endpoints alone cannot see
# it: the bytes at the end are the right bytes. Only the concurrent observer can.
g6s_s3_partial_destination() {  # delivery
  local d="$1" out rc=0
  g6s_world
  g6s_partial_writer "$G6T_W/standin" "$G6T_W/exports" 2
  g6s_seal "$d" "$G6T_W/standin"
  out="$(g6s_route "$d" 2>&1)" || rc=$?
  [ "$rc" = 1 ] || { printf 's3-partial -> a half-written destination ended %s, not FAIL\n' "$rc"
                     return 1; }
  g6_has "$out" 'half-written state' \
    || { printf 's3-partial -> the failure does not name the half-written destination\n'
         return 1; }
  return 0
}

# ------------------------------------------------------------------ calibration

# Without a sanction the calibration must do NOTHING — not a device, not a directory. The proof
# is the stub call log, which records every privileged call anyone made in this world.
g6s_cal_no_sanction() {  # delivery
  local d="$1" out rc=0
  g6s_sealed_world "$d"
  unset G6_SANCTION
  out="$(G6_SANCTION= bash "$d/g6-controller.sh" calibrate --mode rehearsal \
           "$G6T_W/cal-out.txt" 2>&1)" || rc=$?
  [ "$rc" != 0 ] || { printf 'cal-no-sanction -> calibrate accepted a run with no sanction\n'
                      return 1; }
  # And it refused BECAUSE there is no sanction. Something further in would refuse an empty
  # sanction too, and a run that stops for the second reason has not shown that the first gate
  # is there at all.
  g6_has "$out" 'refuses without a sanction' \
    || { printf 'cal-no-sanction -> it refused for another reason: %s\n' \
           "$(printf '%s' "$out" | tail -1)"; return 1; }
  local t n
  for t in losetup mkfs.ext4 mount; do
    n="$(g6s_calls "$t")"
    [ "${n:-0}" = 0 ] || { printf 'cal-no-sanction -> %s ran %s time(s) without a sanction\n' "$t" "$n"
                           return 1; }
  done
  [ ! -e "$G6_REMOTE_ROOT/g6-calibration-image" ] \
    || { printf 'cal-no-sanction -> the calibration image directory was created\n'; return 1; }
  [ ! -e "$G6_WORK/calibration" ] \
    || { printf 'cal-no-sanction -> the calibration work directory was created\n'; return 1; }
  return 0
}

# The manifest's own numbers, put back through the frozen formula by this suite rather than
# compared against the formula string the manifest prints about itself.
g6s_cal_formula() {  # delivery
  local d="$1" m t1 t2 g1 g2 w1 w2
  g6s_sealed_world "$d"
  m="$G6T_W/cal-formula.txt"
  G6T_FAKE_ELAPSED="0:05.00" bash "$d/g6-controller.sh" calibrate --mode rehearsal "$m" \
    >/dev/null 2>&1 || { printf 'cal-formula -> the calibration route did not complete\n'; return 1; }
  t1="$(awk -F'\t' '$1 == "elapsed-S1" { print $2 }' "$m")"
  t2="$(awk -F'\t' '$1 == "elapsed-S2" { print $2 }' "$m")"
  g1="$(awk -F'\t' '$1 == "guard-S1" { print $2 }' "$m")"
  g2="$(awk -F'\t' '$1 == "guard-S2" { print $2 }' "$m")"
  case "$t1$t2$g1$g2" in ''|*[!0-9]*) printf 'cal-formula -> the manifest carries no numbers\n'
                                      return 1 ;; esac
  w1=$(( 4 * 100 * t1 )); [ "$w1" -lt 900 ] && w1=900
  w2=$(( 4 * 100 * t2 )); [ "$w2" -lt 900 ] && w2=900
  [ "$g1" = "$w1" ] || { printf 'cal-formula -> guard-S1 is %s, the formula over t=%s gives %s\n' \
                           "$g1" "$t1" "$w1"; return 1; }
  [ "$g2" = "$w2" ] || { printf 'cal-formula -> guard-S2 is %s, the formula over t=%s gives %s\n' \
                           "$g2" "$t2" "$w2"; return 1; }
  return 0
}

# ------------------------------------------------------------------ lifecycle

g6s_lc_loop_partition() {  # delivery
  local d="$1"; g6s_world
  G6_LOOP_DEV=/dev/loop7p1 bash "$d/g6-image-lib.sh" prepare 2>&1
}

g6s_lc_uuid_shape() {  # delivery
  local d="$1"; g6s_world
  G6_UUID=1-2-3-4-5 bash "$d/g6-image-lib.sh" prepare 2>&1
}

g6s_lc_chain() {  # delivery -> a mounted chain in a fresh world
  local d="$1"
  g6s_world
  g6s_lib "$d" prepare >/dev/null 2>&1 && g6s_lib "$d" attach >/dev/null 2>&1 \
    && g6s_lib "$d" format >/dev/null 2>&1 && g6s_lib "$d" mount >/dev/null 2>&1
}

# The image replaced at the same path by a file of the same size. The name matches, the size
# matches, and it is a different file.
# The chain stops at PREPARED on purpose. Over a chain that reaches ATTACHED the kernel's own
# backing inode is wrong too, so both copies refuse and the mutation proves nothing about the
# guard it names: what is under test here is the PREPARED half of verify, on its own.
#
# The replacement is written under another name and renamed over the image, because rm+create
# usually gets the very same inode back and a scenario that depends on which inode the allocator
# hands out is not a scenario.
g6s_lc_image_devino() {  # delivery
  local d="$1"; g6s_world
  g6s_lib "$d" prepare >/dev/null 2>&1
  local sz; sz="$(stat -c '%s' "$G6_IMAGE")"
  "${G6_TRUNCATE:-truncate}" -s "$sz" "$G6_IMAGE.other"
  mv -f "$G6_IMAGE.other" "$G6_IMAGE"
  g6s_lib "$d" verify 2>&1
}

g6s_lc_image_missing() {  # delivery
  local d="$1"; g6s_world
  g6s_lib "$d" prepare >/dev/null 2>&1
  rm -f "$G6_IMAGE"
  g6s_lib "$d" verify 2>&1
}

g6s_lc_backing_dev() {  # delivery
  local d="$1"; g6s_lc_chain "$d"
  G6T_FAKE_BACKING_DEV=9:9 bash "$d/g6-image-lib.sh" verify 2>&1
}

g6s_lc_mount_fstype() {  # delivery
  local d="$1"; g6s_world
  g6s_lib "$d" prepare >/dev/null 2>&1; g6s_lib "$d" attach >/dev/null 2>&1
  g6s_lib "$d" format >/dev/null 2>&1
  G6T_FAKE_FSTYPE=xfs bash "$d/g6-image-lib.sh" mount 2>&1
}

g6s_lc_mount_devno() {  # delivery
  local d="$1"; g6s_world
  g6s_lib "$d" prepare >/dev/null 2>&1; g6s_lib "$d" attach >/dev/null 2>&1
  g6s_lib "$d" format >/dev/null 2>&1
  G6T_FAKE_MOUNT_DEVNO=9:9 bash "$d/g6-image-lib.sh" mount 2>&1
}

# Resume after an interruption at each of the four steps. The chain is rebuilt from durable state
# alone: resume must name the step that is missing, and that step must then complete.
g6s_resume_at() {  # delivery tag steps... -- next
  local d="$1" tag="$2"; shift 2
  local next="${!#}" s
  g6s_world
  for s in "$@"; do
    [ "$s" = "$next" ] && break
    g6s_lib "$d" "$s" >/dev/null 2>&1 \
      || { printf '%s -> the chain could not be built as far as %s\n' "$tag" "$s"; return 1; }
  done
  local rout; rout="$(g6s_lib "$d" resume 2>&1)"
  g6_has "$rout" "next=$next" \
    || { printf '%s -> resume does not name %s as the next step: %s\n' \
           "$tag" "$next" "$(printf '%s' "$rout" | tail -1)"; return 1; }
  g6s_lib "$d" "$next" >/dev/null 2>&1 \
    || { printf '%s -> the step resume named did not complete\n' "$tag"; return 1; }
  return 0
}

g6s_lc_resume_attach()   { g6s_resume_at "$1" resume-attach   prepare attach; }
g6s_lc_resume_format()   { g6s_resume_at "$1" resume-format   prepare attach format; }
g6s_lc_resume_mount()    { g6s_resume_at "$1" resume-mount    prepare attach format mount; }
g6s_lc_resume_teardown() { g6s_resume_at "$1" resume-teardown prepare attach format mount teardown; }

# Teardown interrupted after each of its own steps. Its records describe what WAS true; a step
# that already happened must not be demanded back.
g6s_teardown_after() {  # delivery tag how-far
  local d="$1" tag="$2" far="$3" out rc=0
  g6s_lc_chain "$d" || { printf '%s -> the chain could not be built\n' "$tag"; return 1; }
  "$G6_UMOUNT" "$G6_MOUNTPOINT" >/dev/null 2>&1
  case "$far" in
    detach|unlink) "$G6_LOSETUP" -d "$G6_LOOP_DEV" >/dev/null 2>&1 ;;
  esac
  case "$far" in
    unlink) rm -f "$G6_IMAGE" ;;
  esac
  out="$(g6s_lib "$d" teardown 2>&1)" || rc=$?
  [ "$rc" = 0 ] \
    || { printf '%s -> teardown could not finish what an interruption left behind\n%s\n' \
           "$tag" "$(printf '%s' "$out" | tail -3)"; return 1; }
  [ -f "$G6_STATE_DIR/TORNDOWN" ] \
    || { printf '%s -> teardown finished without publishing TORNDOWN\n' "$tag"; return 1; }
  return 0
}

g6s_lc_crash_after_umount() { g6s_teardown_after "$1" crash-after-umount umount; }
g6s_lc_crash_after_detach() { g6s_teardown_after "$1" crash-after-detach detach; }
g6s_lc_crash_after_unlink() { g6s_teardown_after "$1" crash-after-unlink unlink; }

# Something that is not ours in the directory the lifecycle owns. The image goes; the directory
# stays; `rmdir || true` used to call that complete.
g6s_lc_dir_residue() {  # delivery
  local d="$1"; g6s_lc_chain "$d"
  printf 'not ours\n' > "$(dirname "$G6_IMAGE")/stray"
  g6s_lib "$d" teardown 2>&1
}

# ------------------------------------------------------------------ provenance

# A checkpoint that was already there. The route may not attribute it to itself, and it must find
# that out before it scans anything.
g6s_prov_pre_existing_state() {  # delivery
  local d="$1" out rc=0
  g6s_sealed_world "$d"
  mkdir -p "$G6_FIXTURE_ROOT/state"
  printf 'not a checkpoint this run made\n' > "$G6_FIXTURE_ROOT/state/dedcom.db"
  out="$(g6s_route "$d" 2>&1)" || rc=$?
  [ "$rc" = 2 ] || { printf 'prov-pre-existing -> a checkpoint that predates the run ended %s\n' \
                       "$rc"; return 1; }
  g6_has "$out" 'a checkpoint already exists' \
    || { printf 'prov-pre-existing -> the refusal does not name the earlier checkpoint\n'
         return 1; }
  [ ! -e "$G6_WORK/scenarios/SCAN.meta" ] \
    || { printf 'prov-pre-existing -> the scan ran anyway\n'; return 1; }
  return 0
}

# The stamp survives, one product table does not. A provenance check that reads user_version and
# stops is satisfied by this database.
g6s_prov_incomplete_schema() {  # delivery
  local d="$1"
  g6s_world
  g6s_schema_dropper "$G6T_W/dropper" dir_omission
  g6s_seal "$d" "$G6T_W/dropper"
  g6s_route "$d" 2>&1
}

# The binary is the sanctioned one on the way in and something else by the time it has finished
# writing the checkpoint.
g6s_prov_candidate_swapped() {  # delivery
  local d="$1"
  g6s_world
  g6s_self_editing_candidate "$G6T_W/self-editing"
  g6s_seal "$d" "$G6T_W/self-editing"
  g6s_route "$d" 2>&1
}

# The receipt's command line, against the guard's own record AND against the line this route
# meant to launch. Agreement with itself is not provenance.
g6s_prov_receipt_argv() {  # delivery
  local d="$1" ra sa expect
  g6s_sealed_world "$d"
  g6s_route "$d" >/dev/null 2>&1 \
    || { printf 'prov-argv -> the route did not complete\n'; return 1; }
  ra="$(awk -F'\t' '$1 == "scan-argv" { print $2 }' "$G6_WORK/RECEIPT" 2>/dev/null)"
  sa="$(head -n 1 "$G6_WORK/scenarios/SCAN.argv" 2>/dev/null)"
  expect="$(printf '%q %q %q %q %q %q' "$G6_BIN" --state-dir "$G6_FIXTURE_ROOT/state" \
              --scan "$G6_FIXTURE_ROOT/data" --no-resume)"
  [ -n "$ra" ] && [ "$ra" = "$sa" ] \
    || { printf 'prov-argv -> the receipt argv is not the guard argv\n'; return 1; }
  [ "$ra" = "$expect" ] \
    || { printf 'prov-argv -> the receipt argv is not the route scan command line\n'; return 1; }
  return 0
}

# ------------------------------------------------------------------ fail-fast and the verdict

# Fail-fast, proved by which steps left evidence of having run. A run that carried on past a
# contradicted postcondition is visible here whatever it recorded about where it stopped.
g6s_ff_nothing_after() {  # delivery
  local d="$1" ran s
  g6s_world
  g6s_badstats_candidate "$G6T_W/badstats"
  g6s_seal "$d" "$G6T_W/badstats"
  g6s_route "$d" >/dev/null 2>&1
  [ "$(g6s_terminal_field verdict)" = FAIL ] \
    || { printf 'fail-fast -> the contradicted postcondition did not end in FAIL\n'; return 1; }
  ran="$(g6s_terminal_field scenarios-ran)"
  [ "$ran" = "SCAN S1" ] \
    || { printf 'fail-fast -> the run continued past the contradicted postcondition: %s\n' "$ran"
         return 1; }
  for s in S2 S3 S4; do
    [ ! -e "$G6_WORK/scenarios/$s.meta" ] \
      || { printf 'fail-fast -> %s left evidence of having run\n' "$s"; return 1; }
  done
  return 0
}

# The scenario stage prints a line per guarded run, so its output is ALWAYS multi-line. The
# verdict has to be exactly one word regardless, and it has to be the same word every time.
g6s_verdict_multiline() {  # delivery
  local d="$1" lines v
  g6s_sealed_world "$d"
  g6s_route "$d" >/dev/null 2>&1
  lines="$(wc -l < "$G6_WORK/scenarios.log" 2>/dev/null || echo 0)"
  [ "${lines:-0}" -ge 4 ] \
    || { printf 'verdict-multiline -> the stage produced %s lines, so nothing was proved\n' "$lines"
         return 1; }
  v="$(g6s_terminal_field verdict)"
  [ "$v" = PASS ] \
    || { printf 'verdict-multiline -> a multi-line stage produced the verdict %s\n' "$v"; return 1; }
  [ "$(g6s_terminal_field code)" = 0 ] \
    || { printf 'verdict-multiline -> the verdict and the code disagree\n'; return 1; }
  return 0
}

# ------------------------------------------------------------------ publisher, part two

# The final name already exists. The pristine refuses on the existence check; with that check
# gone the KERNEL must still refuse, because link() into an occupied name is an error and not a
# silent replacement. Both refuse — what changes is which of the two did it.
g6s_pub_physical_no_overwrite() {  # delivery
  local d="$1" p="$WORK/no$RANDOM"; mkdir -p "$p"
  printf 'the first record\n' | "$d/g6-publish-record.py" --dir "$p" --name REC >/dev/null 2>&1
  printf 'the second record\n' | "$d/g6-publish-record.py" --dir "$p" --name REC 2>&1
}

# The record is still there and still the right size — and its seal no longer verifies. Re-entry
# has to look at the seal, not only at the name and the length.
g6s_pub_terminal_unsealed() {  # delivery
  local d="$1" status
  g6s_sealed_world "$d"
  g6s_route "$d" >/dev/null 2>&1
  printf 'appended\n' >> "$G6_WORK/TERMINAL"
  status="$(g6s_record_status "$d" "$G6_WORK/PUBSTATE" "$G6_WORK")"
  [ "$status" = unsealed ] \
    || { printf 'terminal-unsealed -> re-entry reports %s, not unsealed\n' "$status"; return 1; }
  return 0
}

# ------------------------------------------------------------------ the route as a whole

# A signal is an outcome. The route must leave a terminal record saying so, with code 2, rather
# than dying where it stands and leaving the evidence directory mid-sentence.
g6s_route_signal() {  # delivery
  local d="$1" pid rc=0 waited=0
  g6s_world
  g6s_slow_candidate "$G6T_W/slow" 5
  g6s_seal "$d" "$G6T_W/slow"
  bash "$d/g6-controller.sh" route --mode rehearsal >"$G6T_W/signal.out" 2>&1 &
  pid=$!
  while [ ! -e "$G6_WORK/scenarios/SCAN.argv" ] && [ "$waited" -lt 300 ]; do
    sleep 0.1; waited=$(( waited + 1 ))
  done
  [ -e "$G6_WORK/scenarios/SCAN.argv" ] \
    || { kill -KILL "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
         printf 'route-signal -> the scan never started, so no signal was delivered to it\n'
         return 1; }
  kill -TERM "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null || rc=$?
  # The status is the signal, not 2. A run cut short proved nothing about the candidate, so the
  # VERDICT is BLOCKED and the record says so — but whatever sent the signal reads the wait
  # status, and §5 of the runbook puts TERM=143 first in its exit precedence. Reporting 2 here
  # would hide a signal behind the code that means "environment".
  [ "$rc" = 143 ] || { printf 'route-signal -> the interrupted route exited %s, not 143
' "$rc"
                       return 1; }
  [ -f "$G6_WORK/TERMINAL" ] \
    || { printf 'route-signal -> the interrupted route left no terminal record\n'; return 1; }
  grep -q 'interrupted by SIG' "$G6_WORK/TERMINAL" \
    || { printf 'route-signal -> the terminal record does not name the signal: %s\n' \
           "$(g6s_terminal_field reason)"; return 1; }
  return 0
}

# A refused contour must leave the machine exactly as it found it — including the directories the
# route would otherwise have created on its way in.
g6s_route_contour_first() {  # delivery
  local d="$1" out
  g6s_sealed_world "$d"
  rm -rf "$G6_WORK"
  out="$(G6_CONTOUR=host bash "$d/g6-controller.sh" route --mode rehearsal 2>&1)"
  [ ! -d "$G6_WORK" ] \
    || { printf 'route-contour-first -> the work directory was created in a refused contour\n'
         return 1; }
  g6_has "$out" 'REFUSED' \
    || { printf 'route-contour-first -> the contour was not refused at all\n'; return 1; }
  return 0
}

# ------------------------------------------------------------------ calibration, part two

# Nothing privileged before every seal has been checked — including the candidate the calibration
# is about to time.
g6s_cal_candidate_pin() {  # delivery
  local d="$1" rc=0 t n
  g6s_sealed_world "$d"
  sed -i "s/^candidate-sha256\t.*/candidate-sha256\t$(printf '0%.0s' $(seq 64))/" "$SANC"
  bash "$d/g6-controller.sh" calibrate --mode rehearsal "$G6T_W/cal-pin.txt" >/dev/null 2>&1 \
    || rc=$?
  [ "$rc" != 0 ] || { printf 'cal-candidate-pin -> calibrate accepted an unpinned candidate\n'
                      return 1; }
  for t in losetup mkfs.ext4 mount; do
    n="$(g6s_calls "$t")"
    [ "${n:-0}" = 0 ] || { printf 'cal-candidate-pin -> %s ran %s time(s) for an unpinned candidate\n' \
                             "$t" "$n"; return 1; }
  done
  return 0
}

# The two contours may not share an object. A plan that points the calibration at the run's own
# image is a plan for one image with two owners.
g6s_cal_kit_separate() {  # delivery
  local d="$1"; g6s_sealed_world "$d"
  sed -i "s|^cal-image\t.*|cal-image\t$G6_IMAGE|" "$PLAN"
  g6t_write_sanction rehearsal "$SANC" "$CAL" "$G6_BIN" \
    "$(bash "$d/g6-controller.sh" bundle | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')" "$PLAN"
  bash "$d/g6-controller.sh" check-sanctions --mode rehearsal 2>&1
}

# The manifest is a durable record like every other. Publishing it into a name that is already
# taken must fail the calibration rather than quietly overwrite the earlier measurement.
g6s_cal_manifest_sealed() {  # delivery
  local d="$1"; g6s_sealed_world "$d"
  printf 'an earlier manifest\n' > "$G6T_W/cal-taken.txt"
  bash "$d/g6-controller.sh" calibrate --mode rehearsal "$G6T_W/cal-taken.txt" 2>&1
}

# The calibration fixture is checked by the independent verifier before anything is timed.
g6s_cal_fixture_verified() {  # delivery
  local d="$1"
  g6s_sealed_world "$d"
  G6_VERIFY_COUNTS=/nonexistent/verify bash "$d/g6-controller.sh" calibrate --mode rehearsal \
    "$G6T_W/cal-fx.txt" 2>&1
}

# A calibration path with a space in it. Nothing in the environment handed to the lifecycle may
# be word split, and this is the case that proves it rather than asserting it.
g6s_cal_no_word_splitting() {  # delivery
  local d="$1" spaced
  g6s_sealed_world "$d"
  spaced="$G6_REMOTE_ROOT/cal dir"
  sed -i "s|^cal-mountpoint\t.*|cal-mountpoint\t$spaced|" "$PLAN"
  g6t_write_sanction rehearsal "$SANC" "$CAL" "$G6_BIN" \
    "$(bash "$d/g6-controller.sh" bundle | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')" "$PLAN"
  bash "$d/g6-controller.sh" calibrate --mode rehearsal "$G6T_W/cal-space.txt" >/dev/null 2>&1 \
    || { printf 'cal-word-splitting -> the calibration failed on a path with a space in it\n'
         return 1; }
  [ ! -e "$G6_REMOTE_ROOT/cal" ] \
    || { printf 'cal-word-splitting -> the path was split: %s exists\n' "$G6_REMOTE_ROOT/cal"
         return 1; }
  return 0
}

# ------------------------------------------------------------------ plan and capacity

g6s_plan_env_override() {  # delivery
  local d="$1"; g6s_sealed_world "$d"
  G6_INODE_RESERVE=1 bash "$d/g6-controller.sh" check-sanctions --mode rehearsal 2>&1
}

g6s_plan_host() {  # delivery
  local d="$1"; g6s_sealed_world "$d"
  sed -i "s|^host\t.*|host\tsome-other-host|" "$PLAN"
  sed -i "s|^host\t.*|host\tsome-other-host|" "$SANC"
  g6t_write_sanction rehearsal "$SANC" "$CAL" "$G6_BIN" \
    "$(bash "$d/g6-controller.sh" bundle | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')" "$PLAN"
  sed -i "s|^host\t.*|host\tsome-other-host|" "$SANC"
  bash "$d/g6-controller.sh" check-sanctions --mode rehearsal 2>&1
}

g6s_plan_work_contained() {  # delivery
  local d="$1"; g6s_sealed_world "$d"
  # Both keys, because the run is given ONE directory for both: moving work-dir alone leaves
  # evidence-dir pointing at the old path, and the disagreement between the plan and the run
  # refuses before containment is ever reached.
  sed -i "s|^work-dir\t.*|work-dir\t/tmp/g6-elsewhere|;s|^evidence-dir\t.*|evidence-dir\t/tmp/g6-elsewhere|" "$PLAN"
  g6t_write_sanction rehearsal "$SANC" "$CAL" "$G6_BIN" \
    "$(bash "$d/g6-controller.sh" bundle | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')" "$PLAN"
  sed -i "s|^work-dir\t.*|work-dir\t/tmp/g6-elsewhere|" "$SANC"
  # The run has to agree with the plan, or the disagreement refuses first and containment is
  # never reached.
  G6_WORK=/tmp/g6-elsewhere bash "$d/g6-controller.sh" check-sanctions --mode rehearsal 2>&1
}

# An inode table too small for the run. The filesystem has room in bytes and cannot hold the
# files, which is the failure that only shows up at the two millionth one.
g6s_plan_inode_total() {  # delivery
  local d="$1" out rc=0
  g6s_sealed_world "$d"
  out="$(G6T_DF_INSIDE_INODES_TOTAL=1000 bash "$d/g6-controller.sh" route --mode rehearsal 2>&1)" \
    || rc=$?
  [ "$rc" = 2 ] || { printf 'plan-inode-total -> a filesystem too small for the run ended %s\n' \
                       "$rc"; return 1; }
  g6_has "$out" 'internal inode total' \
    || { printf 'plan-inode-total -> the refusal does not name the inode total\n'; return 1; }
  return 0
}

# Capacity is asked BEFORE the image is created, so a run that cannot fit leaves nothing behind.
g6s_plan_capacity_before_create() {  # delivery
  local d="$1" rc=0
  g6s_sealed_world "$d"
  G6T_DF_OUTSIDE_BYTES=1000 bash "$d/g6-controller.sh" route --mode rehearsal >/dev/null 2>&1 \
    || rc=$?
  [ "$rc" = 2 ] || { printf 'capacity-before-create -> a starved run exited %s, not 2\n' "$rc"
                     return 1; }
  [ ! -e "$G6_IMAGE" ] \
    || { printf 'capacity-before-create -> the image was created before capacity was checked\n'
         return 1; }
  [ ! -f "$G6_STATE_DIR/PREPARED" ] \
    || { printf 'capacity-before-create -> the lifecycle started before capacity was checked\n'
         return 1; }
  return 0
}

# ------------------------------------------------------------------ lifecycle, part two

# The image is replaced between prepare and attach. The path still spells the same thing and the
# device would back a file the plan never named.
# The device bound to a file that is not the one the plan named, while the path spelling still
# agrees. Swapping the image before the attach cannot produce this: losetup binds whatever is at
# the path, so the kernel and the plan then agree again. What is under test is the comparison of
# the kernel's OWN backing inode against the planned image, so that is the field the bench moves.
g6s_lc_attach_inode_binding() {  # delivery
  local d="$1"
  g6s_world
  g6s_lib "$d" prepare >/dev/null 2>&1
  G6T_FAKE_BACKING_INO=123456789 bash "$d/g6-image-lib.sh" attach 2>&1
}

g6s_lc_format_fstype() {  # delivery
  local d="$1"; g6s_world
  g6s_lib "$d" prepare >/dev/null 2>&1; g6s_lib "$d" attach >/dev/null 2>&1
  G6T_FAKE_FSTYPE=xfs bash "$d/g6-image-lib.sh" format 2>&1
}

g6s_lc_format_inode_total() {  # delivery
  local d="$1"; g6s_world
  g6s_lib "$d" prepare >/dev/null 2>&1; g6s_lib "$d" attach >/dev/null 2>&1
  G6_MIN_INODES=2492490 G6T_FAKE_INODES=1000 bash "$d/g6-image-lib.sh" format 2>&1
}

g6s_lc_state_contained() {  # delivery
  local d="$1"; g6s_world
  mkdir -p "$G6T_W/outside-state"
  G6_STATE_DIR="$G6T_W/outside-state" bash "$d/g6-image-lib.sh" prepare 2>&1
}

g6s_lc_torndown_seal() {  # delivery
  local d="$1"; g6s_lc_chain "$d"
  g6s_lib "$d" teardown >/dev/null 2>&1
  printf 'appended\n' >> "$G6_STATE_DIR/TORNDOWN"
  g6s_lib "$d" teardown 2>&1
}

# A detach that reports success and leaves the device bound.
g6s_lc_detach_ineffective() {  # delivery
  local d="$1"; g6s_lc_chain "$d"
  G6T_KEEP_BACKING=1 bash "$d/g6-image-lib.sh" teardown 2>&1
}

# ------------------------------------------------------------------ provenance, part two

# The record published BEFORE the scan, and the scan that actually ran, are the same command.
g6s_prov_invocation_record() {  # delivery
  local d="$1" inv sa
  g6s_sealed_world "$d"
  g6s_route "$d" >/dev/null 2>&1 \
    || { printf 'prov-invocation -> the route did not complete\n'; return 1; }
  [ -f "$G6_WORK/INVOCATION" ] \
    || { printf 'prov-invocation -> nothing was recorded before the scan\n'; return 1; }
  inv="$(awk -F'\t' '$1 == "scan-argv" { print $2 }' "$G6_WORK/INVOCATION")"
  sa="$(head -n 1 "$G6_WORK/scenarios/SCAN.argv" 2>/dev/null)"
  [ -n "$inv" ] && [ "$inv" = "$sa" ] \
    || { printf 'prov-invocation -> the announced scan is not the scan that ran\n'; return 1; }
  [ -f "$G6_WORK/RECEIPT" ] && grep -q '^provenance-not-from' "$G6_WORK/RECEIPT" \
    || { printf 'prov-invocation -> the receipt does not say what its provenance is NOT from\n'
         return 1; }
  return 0
}

# The stamp and the table names survive; one index does not. A contract that stops at four names
# cannot see this, and the route must still refuse.
# One witness per element of the v5 floor. Each takes exactly one thing away, so each refusal
# names exactly one thing; a single scenario dropping several would prove only that SOMETHING
# was noticed.
g6s_prov_column_scan_trashed()      { g6s_prov_column_gone "$1" scan trashed; }
g6s_prov_column_hash_failures()     { g6s_prov_column_gone "$1" scan_stats hash_failures; }
g6s_prov_column_materialized()      { g6s_prov_column_gone "$1" scan_stats results_materialized; }
g6s_prov_column_cand_files_total()  { g6s_prov_column_gone "$1" scan_stats cand_files_total; }
g6s_prov_column_cand_bytes_total()  { g6s_prov_column_gone "$1" scan_stats cand_bytes_total; }
g6s_prov_column_cand_files_hashed() { g6s_prov_column_gone "$1" scan_stats cand_files_hashed; }
g6s_prov_column_cand_bytes_hashed() { g6s_prov_column_gone "$1" scan_stats cand_bytes_hashed; }

g6s_prov_column_gone() {  # delivery table column
  local d="$1"
  g6s_world
  g6s_column_dropper "$G6T_W/column-dropper" "$2" "$3"
  g6s_seal "$d" "$G6T_W/column-dropper"
  g6s_route "$d" 2>&1
}

g6s_prov_index_reuse_identity() {  # delivery
  local d="$1"
  g6s_world
  g6s_index_dropper "$G6T_W/index-dropper" file_reuse_identity
  g6s_seal "$d" "$G6T_W/index-dropper"
  g6s_route "$d" 2>&1
}

g6s_prov_structural_v5() {  # delivery
  local d="$1"
  g6s_world
  g6s_index_dropper "$G6T_W/index-dropper" file_hash_path
  g6s_seal "$d" "$G6T_W/index-dropper"
  g6s_route "$d" 2>&1
}

# The receipt is checked by the program that reads the database, not only by the one that wrote
# the receipt.
g6s_prov_receipt_in_verifier() {  # delivery
  local d="$1" db
  g6s_world
  db="$G6T_W/prov-db"; mkdir -p "$db"
  "$DEDCOM" --state-dir "$db" --scan "$G6T_W" --no-resume >/dev/null 2>&1
  # Properly sealed, and about somebody else's checkpoint. A receipt with no seal at all is
  # caught by the seal check instead and says nothing about whether the CONTENT is ever compared
  # with the database in front of it.
  rm -rf "$G6T_W/foreign"; mkdir -p "$G6T_W/foreign"
  { printf 'provenance\tsomething\n'
    printf 'checkpoint\t/somewhere/else/dedcom.db\n'
    printf 'scan-argv\tsomething\n'
    printf 'candidate-sha256\tdeadbeef\n'
  } | "$d/g6-publish-record.py" --dir "$G6T_W/foreign" --name RECEIPT >/dev/null 2>&1
  "$d/g6-verify-counts.py" --db "$db/dedcom.db" --groups 0 --members-per-group 2 --singletons 0 \
    --receipt "$G6T_W/foreign/RECEIPT" 2>&1
}

# A database that cannot be read is an environment problem, and it is reported as one sentence.
g6s_prov_sqlite_blocked() {  # delivery
  local d="$1" out rc=0
  g6s_world
  # A FILE that is not a database, not a directory: sqlite refuses a directory at connect(), and
  # that is a different sentence from the one under test. What has to be reported as one line is
  # a handle that opens and then cannot answer the first question about its schema.
  printf 'this is not an SQLite database\n' > "$G6T_W/not-a-db"
  out="$("$d/g6-verify-counts.py" --db "$G6T_W/not-a-db" --groups 1 --members-per-group 2 \
           --singletons 1 2>&1)" || rc=$?
  printf '%s\n' "$out"
  g6_has "$out" Traceback && printf 'prov-sqlite -> it printed a traceback\n'
  # The verifier's own status is the answer, and it is passed through rather than swallowed: this
  # scenario is about WHICH refusal a broken database gets, and a scenario that always exits 0
  # cannot tell one refusal from another.
  return "$rc"
}

# ------------------------------------------------------------------ the write path itself

# `write_all` cannot be exercised from outside — the kernel writes what it is given — so these
# drive it directly with os.write replaced. The no-progress cases run under a bounded timeout,
# because the failure they are about is a loop that never returns.
g6s_write_short() {  # delivery
  local d="$1"
  timeout 30 python3 "$HERE/test-g6-write-faults.py" "$d" short 2>&1 \
    || { printf 'write-short -> the short-write case did not complete\n'; return 1; }
}

g6s_write_no_progress() {  # delivery
  local d="$1" out rc=0
  out="$(timeout 15 python3 "$HERE/test-g6-write-faults.py" "$d" zero 2>&1)" || rc=$?
  [ "$rc" != 124 ] || { printf 'write-zero -> the writer hung instead of failing\n'; return 1; }
  [ "$rc" = 0 ] || { printf 'write-zero -> %s\n' "$(printf '%s' "$out" | tail -1)"; return 1; }
  return 0
}

g6s_write_publish_nothing_left() {  # delivery
  local d="$1" out rc=0
  out="$(timeout 15 python3 "$HERE/test-g6-write-faults.py" "$d" publish 2>&1)" || rc=$?
  [ "$rc" != 124 ] || { printf 'write-publish -> the publication hung instead of failing\n'
                        return 1; }
  [ "$rc" = 0 ] || { printf 'write-publish -> %s\n' "$(printf '%s' "$out" | tail -1)"; return 1; }
  return 0
}

# ------------------------------------------------------------------ the claim on a directory

# Twelve BEGINs at once over one evidence directory. Exactly one of them started the run; the
# other eleven have to find that out and say so, the state file has to be the winner's, and
# nobody may leave a temporary behind. Nothing here is timing-sensitive: link() into an existing
# name cannot succeed twice, so the count is one however the twelve happen to interleave.
g6s_pub_begin_concurrent() {  # delivery
  local d="$1" p="$WORK/bc$RANDOM" sd rd i rc zero=0 refused=0 other="" state left
  sd="$p/state"; rd="$p/rc"; mkdir -p "$sd" "$rd"
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    ( rc=0
      "$d/g6-publish-record.py" --begin --state-file "$sd/PUBSTATE" >/dev/null 2>&1 || rc=$?
      printf '%s\n' "$rc" > "$rd/$i" ) &
  done
  wait
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    rc="$(cat "$rd/$i" 2>/dev/null)"
    case "$rc" in
      0) zero=$(( zero + 1 )) ;;
      2) refused=$(( refused + 1 )) ;;
      *) other="$other $i:${rc:-nothing}" ;;
    esac
  done
  [ -z "$other" ] \
    || { printf 'begin-concurrent -> exits that are neither 0 nor 2:%s\n' "$other"; return 1; }
  [ "$zero" = 1 ] \
    || { printf 'begin-concurrent -> %s of 12 concurrent BEGINs claimed the run, not 1\n' "$zero"
         return 1; }
  [ "$refused" = 11 ] \
    || { printf 'begin-concurrent -> %s losers refused, not 11\n' "$refused"; return 1; }
  state="$(g6s_state_word "$d" "$sd/PUBSTATE")"
  [ "$state" = RUNNING ] \
    || { printf 'begin-concurrent -> the state reads %s, not RUNNING\n' "$state"; return 1; }
  left="$(ls -A "$sd" | grep -v '^PUBSTATE$' | tr '\n' ' ')"
  [ -z "$left" ] \
    || { printf 'begin-concurrent -> temporaries were left behind: %s\n' "$left"; return 1; }
  return 0
}

# The interleaving itself, without waiting for it to happen: the state file is THERE and the run
# about to write it read NOT_STARTED. That is the one ordering no amount of checking before the
# write can rule out, so the write is what has to refuse.
g6s_pub_begin_create_only() {  # delivery
  local d="$1" out rc=0
  out="$(timeout 15 python3 "$HERE/test-g6-write-faults.py" "$d" claim 2>&1)" || rc=$?
  [ "$rc" != 124 ] || { printf 'begin-claim -> the claim hung instead of refusing\n'; return 1; }
  [ "$rc" = 0 ] || { printf 'begin-claim -> %s\n' "$(printf '%s' "$out" | tail -1)"; return 1; }
  return 0
}

# ------------------------------------------------------------------ durable run state

# A run killed between BEGIN and the terminal record. What it must leave behind is a directory
# that says a run started and did not finish — not one that looks untouched.
g6s_route_begin_durable() {  # delivery
  local d="$1" pid waited=0 state rc=0
  g6s_world
  g6s_slow_candidate "$G6T_W/slow" 5
  g6s_seal "$d" "$G6T_W/slow"
  bash "$d/g6-controller.sh" route --mode rehearsal >"$G6T_W/begin.out" 2>&1 &
  pid=$!
  while [ ! -e "$G6_WORK/scenarios/SCAN.argv" ] && [ "$waited" -lt 300 ]; do
    sleep 0.1; waited=$(( waited + 1 ))
  done
  [ -e "$G6_WORK/scenarios/SCAN.argv" ] \
    || { kill -KILL "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
         printf 'route-begin -> the run never reached the scan\n'; return 1; }
  kill -KILL "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  state="$("$d/g6-publish-record.py" --query-state --state-file "$G6_WORK/PUBSTATE" 2>&1 \
            | awk -F'\t' '$1 == "STATE" { print $2 }')"
  [ "$state" = RUNNING ] \
    || { printf 'route-begin -> after a hard kill the state reads %s\n' "$state"; return 1; }
  out="$(bash "$d/g6-controller.sh" route --mode rehearsal 2>&1)" || rc=$?
  [ "$rc" = 2 ] || { printf 'route-begin -> a fresh route over an unfinished run exited %s\n' "$rc"
                     return 1; }
  g6_has "$out" 'started and did not finish' \
    || { printf 'route-begin -> the refusal does not name the unfinished run\n'; return 1; }
  return 0
}

# PRESTART exits leave nothing at all: no state, no record, no image. This is the honest half of
# "every exit is terminalized" — the half that is true.
g6s_route_prestart_leaves_nothing() {  # delivery
  local d="$1"
  g6s_sealed_world "$d"
  G6_CONTOUR=host bash "$d/g6-controller.sh" route --mode rehearsal >/dev/null 2>&1
  [ ! -e "$G6_WORK/TERMINAL" ] \
    || { printf 'route-prestart -> a refused contour left a terminal record\n'; return 1; }
  [ ! -e "$G6_WORK/PUBSTATE" ] \
    || { printf 'route-prestart -> a refused contour left a run state\n'; return 1; }
  [ ! -e "$G6_IMAGE" ] \
    || { printf 'route-prestart -> a refused contour left an image\n'; return 1; }
  return 0
}

# An interrupted run is an inspection, not a second attempt.
#
# There was a controller `recover` here that continued the durable chain by itself. It resumed on
# a state of RUNNING without asking whether a TERMINAL record already existed, so a run whose
# record was published and whose state update then failed could be entered again — and the
# candidate invoked a second time, over the evidence of the first. What the run left behind is a
# question for a human holding the inventory; the harness does not answer it by running the
# workload again.
g6s_lc_interrupted_blocked() {  # delivery
  local d="$1" rc=0 losetups out
  g6s_sealed_world "$d"
  g6s_lib "$d" prepare >/dev/null 2>&1 || { printf 'lc-interrupted -> prepare failed\n'; return 1; }
  g6s_lib "$d" attach  >/dev/null 2>&1 || { printf 'lc-interrupted -> attach failed\n'; return 1; }
  "$d/g6-publish-record.py" --begin --state-file "$G6_WORK/PUBSTATE" >/dev/null 2>&1 \
    || { printf 'lc-interrupted -> the interrupted run could not be announced\n'; return 1; }
  losetups="$(g6s_attach_calls)"
  out="$(bash "$d/g6-controller.sh" route --mode rehearsal 2>&1)" || rc=$?
  [ "$rc" = 2 ] \
    || { printf 'lc-interrupted -> re-entry exited %s, not BLOCKED\n%s\n' "$rc" \
           "$(printf '%s' "$out" | tail -3)"; return 1; }
  g6_has "$out" 'started and did not finish' \
    || { printf 'lc-interrupted -> the refusal does not say what it found\n'; return 1; }
  g6_has "$out" 'INVENTORY:' \
    || { printf 'lc-interrupted -> the refusal carries no inventory for a human to read\n'
         return 1; }
  [ "$(g6s_attach_calls)" = "$losetups" ] \
    || { printf 'lc-interrupted -> re-entry touched the device\n'; return 1; }
  [ ! -e "$G6_WORK/TERMINAL" ] \
    || { printf 'lc-interrupted -> a refusal that touched nothing wrote a terminal record\n'
         return 1; }
  return 0
}

# ------------------------------------------------------------------ S3, part two

# The observer is driven DIRECTLY, with the stop file already in place so the sampling loop is
# over before it starts. Whatever is in the log when it exits is therefore exactly what it wrote
# before announcing itself, which is the whole of what the ordering claims.
#
# Through a route this cannot be settled at all: the loop begins sampling the instant READY is
# written, so by the time anything counts the log the count is above zero either way, and an
# observer that announced itself first would look identical to one that did not.
g6s_s3_ready_after_sample() {  # delivery
  local d="$1" w n
  g6s_world
  w="$G6T_W/obs$RANDOM"; mkdir -p "$w"
  printf 'the destination as it was\n' > "$w/dest"
  : > "$w/log"; : > "$w/stop"
  timeout 30 python3 "$d/g6-observe-destination.py" "$w/dest" "$w/log" "$w/stop" "$w/ready" \
    || { printf 's3-ready -> the observer did not complete\n'; return 1; }
  [ -e "$w/ready" ] \
    || { printf 's3-ready -> the observer never signalled ready\n'; return 1; }
  n="$(wc -l < "$w/log")"
  [ "${n:-0}" -ge 1 ] \
    || { printf 's3-ready -> ready was signalled with %s samples in the log\n' "${n:-none}"
         return 1; }
  return 0
}

# An observer that ignores the stop file. The run must reap it on a deadline and finish; without
# a deadline it waits for a process that never leaves.
#
# It is written in PYTHON because that is what the controller launches it with. A bash stand-in
# is not a hung observer, it is a SyntaxError: it dies at once, the run never sees READY, and
# both copies then take the "nothing could witness S3" exit instead.
g6s_s3_hung_observer() {  # delivery
  local d="$1" rc=0
  g6s_sealed_world "$d"
  { printf 'import sys, time\n'
    printf 'dest, log, stop, ready = sys.argv[1:5]\n'
    printf 'open(log, "a").write("0 0 x\\n")\n'
    printf 'open(ready, "w").write("ready\\n")\n'
    printf 'while True:\n'
    printf '    time.sleep(1)\n'
  } > "$G6T_W/hung-observer.py"
  timeout 180 env G6_OBSERVE="$G6T_W/hung-observer.py" \
    bash "$d/g6-controller.sh" route --mode rehearsal >/dev/null 2>&1 || rc=$?
  [ "$rc" != 124 ] \
    || { printf 's3-hung -> the run never returned from waiting on its own observer\n'; return 1; }
  [ -f "$G6_WORK/TERMINAL" ] \
    || { printf 's3-hung -> the run left no terminal record\n'; return 1; }
  return 0
}

# ------------------------------------------------------------------ calibration, part three

# The two contours have different requirements. Four gigabytes free is enough for the
# calibration and not for the run, and that is exactly what a separate contour means.
g6s_cal_own_numbers() {  # delivery
  local d="$1" rc=0
  g6s_sealed_world "$d"
  G6T_DF_OUTSIDE_BYTES=4000000000 bash "$d/g6-controller.sh" calibrate --mode rehearsal \
    "$G6T_W/cal-own.txt" >/dev/null 2>&1 \
    || { printf 'cal-own -> the calibration refused capacity that is enough for it\n'; return 1; }
  G6T_DF_OUTSIDE_BYTES=4000000000 bash "$d/g6-controller.sh" route --mode rehearsal \
    >/dev/null 2>&1 || rc=$?
  [ "$rc" = 2 ] \
    || { printf 'cal-own -> the run accepted capacity that is only enough for the calibration\n'
         return 1; }
  return 0
}

g6s_cal_guarded_scan() {  # delivery
  local d="$1" m
  g6s_sealed_world "$d"
  bash "$d/g6-controller.sh" calibrate --mode rehearsal "$G6T_W/cal-g.txt" >/dev/null 2>&1 \
    || { printf 'cal-guard -> the calibration did not complete\n'; return 1; }
  m="$G6_WORK/calibration/CALSCAN.meta"
  { [ -s "$m" ] && grep -q '^class	' "$m" && grep -q '^raw-exit	' "$m" \
    && [ -f "$G6_WORK/calibration/CALSCAN.out" ]; } \
    || { printf 'cal-guard -> the calibration scan left no guard evidence\n'; return 1; }
  return 0
}

# The generator is measured between batches on this contour too: a hook that starts refusing
# part-way through must stop the calibration fixture.
g6s_cal_capacity_hook() {  # delivery
  local d="$1" out calmnt
  g6s_sealed_world "$d"
  # The calibration builds ITS fixture on ITS own mountpoint, so that is the filesystem the
  # starvation has to happen on. Starving the run's mountpoint starves a filesystem the
  # calibration never asks about, and the counter stays at zero however far it gets.
  calmnt="$(awk -F'\t' '$1 == "cal-mountpoint" { print $2 }' "$PLAN")"
  out="$(G6T_INSIDE="$calmnt" G6T_DF_STARVE_AFTER=3 bash "$d/g6-controller.sh" calibrate --mode rehearsal \
           "$G6T_W/cal-h.txt" 2>&1)" \
    && { printf 'cal-hook -> the calibration finished with no capacity between batches\n'
         return 1; }
  g6_has "$out" 'fixture did not build' \
    || { printf 'cal-hook -> the calibration stopped for another reason: %s\n' \
           "$(printf '%s' "$out" | tail -1)"; return 1; }
  return 0
}

# The calibration formats ITS geometry, not the run's.
g6s_cal_geometry() {  # delivery
  local d="$1" want
  g6s_sealed_world "$d"
  want="$(awk -F'\t' '$1 == "cal-requested-inodes" { print $2 }' "$PLAN")"
  bash "$d/g6-controller.sh" calibrate --mode rehearsal "$G6T_W/cal-geo.txt" >/dev/null 2>&1 \
    || { printf 'cal-geometry -> the calibration did not complete\n'; return 1; }
  grep -q "^mkfs.ext4 .*-N $want " "$G6T_LOG" \
    || { printf 'cal-geometry -> mkfs was not asked for %s inodes: %s\n' "$want" \
           "$(grep '^mkfs.ext4' "$G6T_LOG" | head -1)"; return 1; }
  return 0
}

# ------------------------------------------------------------------ host identity

# A live run may not be told which machine it is on.
g6s_plan_host_live() {  # delivery
  local d="$1"
  g6s_world
  CAL="$G6T_W/cal.txt"; SANC="$G6T_W/sanc.txt"; PLAN="$G6T_W/plan.txt"
  g6t_write_calibration live "$CAL"
  g6t_write_plan "$PLAN" live
  sed -i "s|^host\t.*|host\tpretend-host|" "$PLAN"
  g6t_write_sanction live "$SANC" "$CAL" "$DEDCOM" \
    "$(bash "$d/g6-controller.sh" bundle | awk -F'\t' '$1 == "bundle-sha256" { print $2 }')" "$PLAN"
  sed -i "s|^host\t.*|host\tpretend-host|" "$SANC"
  export G6_CALIBRATION="$CAL" G6_SANCTION="$SANC" G6_RESOURCE_PLAN="$PLAN"
  export G6_BIN="$DEDCOM" G6_NOW=5000
  G6_CONTOUR=host G6_HOST_ID=pretend-host bash "$d/g6-controller.sh" check-sanctions --mode live 2>&1
}

# ------------------------------------------------------------------ provenance, part three

g6s_prov_receipt_seal() {  # delivery
  local d="$1" db
  g6s_world
  db="$G6T_W/seal-db"; mkdir -p "$db"
  "$DEDCOM" --state-dir "$db" --scan "$G6T_W" --no-resume >/dev/null 2>&1
  # Sealed in shape, wrong in digest: exactly what a record that was edited after publication
  # looks like. A receipt with no seal lines at all would be caught by the shape check instead,
  # and would say nothing about whether the digest is ever compared.
  # The size is MEASURED, not computed by hand. A length that is merely close is caught by the
  # size half of the seal, and the digest — the half this row is about — is then never reached,
  # in either copy.
  { printf 'checkpoint\t%s\n' "$db/dedcom.db"
    printf 'scan-argv\tx\ncandidate-sha256\ty\ninvocation-sha256\tz\n'
  } > "$G6T_W/sealed-body"
  { cat "$G6T_W/sealed-body"
    printf 'record-size\t%s\n' "$(stat -c '%s' "$G6T_W/sealed-body")"
    printf 'record-sha256\t%s\n' "$(printf '0%.0s' $(seq 64))"
  } > "$G6T_W/edited-receipt"
  "$d/g6-verify-counts.py" --db "$db/dedcom.db" --groups 0 --members-per-group 2 --singletons 0 \
    --receipt "$G6T_W/edited-receipt" 2>&1
}

g6s_prov_invocation_binding() {  # delivery
  local d="$1"
  g6s_sealed_world "$d"
  g6s_route "$d" >/dev/null 2>&1 \
    || { printf 'prov-binding -> the route did not complete\n' >&2; }
  # A receipt that is sealed, about this checkpoint, and names another invocation.
  sed 's|^invocation-sha256\t.*|invocation-sha256\t0000000000000000000000000000000000000000000000000000000000000000|' \
    "$G6_WORK/RECEIPT" | grep -v '^record-' > "$G6T_W/receipt-body"
  rm -f "$G6T_W/rebuilt/RECEIPT"; mkdir -p "$G6T_W/rebuilt"
  "$d/g6-publish-record.py" --dir "$G6T_W/rebuilt" --name RECEIPT < "$G6T_W/receipt-body" \
    >/dev/null 2>&1
  "$d/g6-verify-counts.py" --db "$G6_FIXTURE_ROOT/state/dedcom.db" \
    --groups 40 --members-per-group 2 --singletons 20 \
    --receipt "$G6T_W/rebuilt/RECEIPT" --invocation "$G6_WORK/INVOCATION" 2>&1
}

# The invocation record corrupted during the run. The receipt is built out of it, so the question
# is whether it is checked before it is read — and the answer is observable without reading a
# single message: either a receipt was published out of an untrusted record, or it was not. A
# verifier that reports the corruption at the end does not un-publish what is already there.
g6s_prov_read_after_verify() {  # delivery
  local d="$1"
  g6s_world
  g6s_invocation_tamperer "$G6T_W/tamperer" "$G6_WORK/INVOCATION"
  g6s_seal "$d" "$G6T_W/tamperer"
  g6s_route "$d" >/dev/null 2>&1
  [ ! -e "$G6_WORK/RECEIPT" ] \
    || { printf 'prov-read-after-verify -> a receipt was published out of a record that does not \
verify\n'; return 1; }
  return 0
}

g6s_prov_index_shape() {  # delivery
  local d="$1"
  g6s_world
  g6s_index_reshaper "$G6T_W/reshaper" file_hash_path file "scan_id, hash"
  g6s_seal "$d" "$G6T_W/reshaper"
  g6s_route "$d" 2>&1
}

g6s_prov_all_columns() {  # delivery
  local d="$1"
  g6s_world
  g6s_column_dropper "$G6T_W/col-dropper" hash_cache updated_at
  g6s_seal "$d" "$G6T_W/col-dropper"
  g6s_route "$d" 2>&1
}

# ------------------------------------------------------------------ the registry
#
# name <TAB> function <TAB> polarity <TAB> cause <TAB> alternative <TAB> pristine-rc/mutant-rc
#
# The cause is a LITERAL substring of the output the pristine copy produces. It is matched with
# grep -F, so nothing here is a pattern.
#
# The last two columns belong to `reclass` and are '-' everywhere else: the cause the mutant must
# fall back to, and the status each copy must exit with. A reclassification is a change of CLASS
# — BLOCKED=2 says the environment is wrong, FAIL=1 says the candidate is — so the class is
# declared here in advance and compared exactly, rather than settled by whether a phrase moved.

g6s_rows() {
cat <<'ROWS'
pub/write-short	g6s_write_short	hold	write-short ->	-	-
pub/write-no-progress	g6s_write_no_progress	hold	write-zero ->	-	-
pub/write-publish-nothing-left	g6s_write_publish_nothing_left	hold	write-publish ->	-	-
pub/begin-concurrent	g6s_pub_begin_concurrent	hold	begin-concurrent ->	-	-
pub/begin-create-only	g6s_pub_begin_create_only	hold	begin-claim ->	-	-
route/begin-durable	g6s_route_begin_durable	hold	route-begin ->	-	-
route/prestart-leaves-nothing	g6s_route_prestart_leaves_nothing	hold	route-prestart ->	-	-
lc/interrupted-blocked	g6s_lc_interrupted_blocked	hold	lc-interrupted ->	-	-
s3/ready-after-sample	g6s_s3_ready_after_sample	hold	s3-ready ->	-	-
s3/hung-observer	g6s_s3_hung_observer	hold	s3-hung ->	-	-
cal/own-numbers	g6s_cal_own_numbers	hold	cal-own ->	-	-
cal/guarded-scan	g6s_cal_guarded_scan	hold	cal-guard ->	-	-
cal/capacity-hook	g6s_cal_capacity_hook	hold	cal-hook ->	-	-
cal/geometry	g6s_cal_geometry	hold	cal-geometry ->	-	-
plan/host-live	g6s_plan_host_live	refuse	the plan is for host	-	-
prov/receipt-seal	g6s_prov_receipt_seal	reclass	the receipt did not verify	there is no invocation record	2/1
prov/invocation-binding	g6s_prov_invocation_binding	refuse	the receipt names invocation	-	-
prov/index-shape	g6s_prov_index_shape	refuse	keys	-	-
prov/all-columns	g6s_prov_all_columns	refuse	hash_cache is missing columns	-	-
pub/partial-write	g6s_pub_partial_write	refuse	records size	-	-
pub/zero-write	g6s_pub_zero_write	refuse	has an empty body	-	-
pub/state-corrupt	g6s_pub_state_corrupt	hold	state-corrupt ->	-	-
pub/state-unreadable	g6s_pub_state_unreadable	hold	state-unreadable ->	-	-
pub/state-unknown	g6s_pub_state_unknown	hold	state-unknown ->	-	-
pub/terminal-deleted	g6s_pub_terminal_deleted	reclass	terminal record has been deleted	record missing)	2/2
pub/terminal-substituted	g6s_pub_terminal_substituted	reclass	terminal record has been substituted	finished run (state	2/2
pub/reentry-0	g6s_pub_reentry_pass	hold	reentry-0 ->	-	-
pub/reentry-1	g6s_pub_reentry_fail	hold	reentry-1 ->	-	-
pub/reentry-2	g6s_pub_reentry_blocked	hold	reentry-2 ->	-	-
s3/partial-destination	g6s_s3_partial_destination	hold	s3-partial ->	-	-
cal/no-sanction	g6s_cal_no_sanction	hold	cal-no-sanction ->	-	-
cal/formula	g6s_cal_formula	hold	cal-formula ->	-	-
lc/loop-partition	g6s_lc_loop_partition	refuse	is not an exact /dev/loopN name	-	-
lc/uuid-shape	g6s_lc_uuid_shape	refuse	is not a uuid	-	-
lc/image-devino	g6s_lc_image_devino	refuse	the image's dev:ino is	-	-
lc/image-missing	g6s_lc_image_missing	refuse	the recorded image	-	-
lc/backing-dev	g6s_lc_backing_dev	refuse	backing device is	-	-
lc/mount-fstype	g6s_lc_mount_fstype	refuse	not the ext4 that was formatted	-	-
lc/mount-devno	g6s_lc_mount_devno	refuse	reports device number	-	-
lc/resume-attach	g6s_lc_resume_attach	hold	resume-attach ->	-	-
lc/resume-format	g6s_lc_resume_format	hold	resume-format ->	-	-
lc/resume-mount	g6s_lc_resume_mount	hold	resume-mount ->	-	-
lc/resume-teardown	g6s_lc_resume_teardown	hold	resume-teardown ->	-	-
lc/crash-after-umount	g6s_lc_crash_after_umount	hold	crash-after-umount ->	-	-
lc/crash-after-detach	g6s_lc_crash_after_detach	hold	crash-after-detach ->	-	-
lc/crash-after-unlink	g6s_lc_crash_after_unlink	hold	crash-after-unlink ->	-	-
lc/dir-residue	g6s_lc_dir_residue	refuse	directory residue remains after teardown	-	-
prov/pre-existing-state	g6s_prov_pre_existing_state	hold	prov-pre-existing ->	-	-
prov/incomplete-schema	g6s_prov_incomplete_schema	reclass	but not the product tables	tables missing	1/1
prov/candidate-swapped	g6s_prov_candidate_swapped	refuse	the candidate changed under the run	-	-
prov/receipt-argv	g6s_prov_receipt_argv	hold	prov-argv ->	-	-
ff/nothing-after	g6s_ff_nothing_after	hold	fail-fast ->	-	-
verdict/multiline	g6s_verdict_multiline	hold	verdict-multiline ->	-	-
pub/physical-no-overwrite	g6s_pub_physical_no_overwrite	reclass	is already published	appeared while it was being written	2/2
pub/terminal-unsealed	g6s_pub_terminal_unsealed	hold	terminal-unsealed ->	-	-
route/signal	g6s_route_signal	hold	route-signal ->	-	-
route/contour-first	g6s_route_contour_first	hold	route-contour-first ->	-	-
cal/candidate-pin	g6s_cal_candidate_pin	hold	cal-candidate-pin ->	-	-
cal/kit-separate	g6s_cal_kit_separate	refuse	the calibration and the run share	-	-
cal/manifest-sealed	g6s_cal_manifest_sealed	refuse	the calibration manifest could not be published	-	-
cal/fixture-verified	g6s_cal_fixture_verified	refuse	does not match its own parameters	-	-
cal/no-word-splitting	g6s_cal_no_word_splitting	hold	cal-word-splitting ->	-	-
plan/env-override	g6s_plan_env_override	refuse	the environment sets	-	-
plan/host	g6s_plan_host	refuse	the plan is for host	-	-
plan/work-contained	g6s_plan_work_contained	refuse	is not under REMOTE_ROOT	-	-
plan/inode-total	g6s_plan_inode_total	hold	plan-inode-total ->	-	-
plan/capacity-before-create	g6s_plan_capacity_before_create	hold	capacity-before-create ->	-	-
lc/attach-inode-binding	g6s_lc_attach_inode_binding	refuse	but the planned image	-	-
lc/format-fstype	g6s_lc_format_fstype	refuse	not the ext4 that was formatted	-	-
lc/format-inode-total	g6s_lc_format_inode_total	refuse	the run needs	-	-
lc/state-contained	g6s_lc_state_contained	refuse	is not under REMOTE_ROOT	-	-
lc/torndown-seal	g6s_lc_torndown_seal	reclass	TORNDOWN is present but does not verify	record 'TORNDOWN' does not verify	2/2
lc/detach-ineffective	g6s_lc_detach_ineffective	reclass	still reports a backing file after detach	is not proven free	2/2
prov/invocation-record	g6s_prov_invocation_record	hold	prov-invocation ->	-	-
prov/read-after-verify	g6s_prov_read_after_verify	hold	prov-read-after-verify ->	-	-
prov/structural-v5	g6s_prov_structural_v5	reclass	indexes missing	does not belong to	1/1
prov/col-scan-trashed	g6s_prov_column_scan_trashed	reclass	scan is missing columns: trashed	indexes missing	1/1
prov/col-hash-failures	g6s_prov_column_hash_failures	reclass	scan_stats is missing columns: hash_failures	indexes missing	1/1
prov/col-materialized	g6s_prov_column_materialized	reclass	scan_stats is missing columns: results_materialized	indexes missing	1/1
prov/col-cand-files-total	g6s_prov_column_cand_files_total	reclass	scan_stats is missing columns: cand_files_total	indexes missing	1/1
prov/col-cand-bytes-total	g6s_prov_column_cand_bytes_total	reclass	scan_stats is missing columns: cand_bytes_total	indexes missing	1/1
prov/col-cand-files-hashed	g6s_prov_column_cand_files_hashed	reclass	scan_stats is missing columns: cand_files_hashed	indexes missing	1/1
prov/col-cand-bytes-hashed	g6s_prov_column_cand_bytes_hashed	reclass	scan_stats is missing columns: cand_bytes_hashed	indexes missing	1/1
prov/idx-reuse-identity	g6s_prov_index_reuse_identity	reclass	indexes missing: file_reuse_identity	does not belong to	1/1
prov/receipt-in-verifier	g6s_prov_receipt_in_verifier	reclass	the receipt is about	BAD files	1/1
prov/sqlite-blocked	g6s_prov_sqlite_blocked	reclass	BLOCKED: the schema of	Traceback	2/1
ROWS
}

g6s_row_field() {  # name column
  g6s_rows | awk -F'\t' -v n="$1" -v c="$2" '$1 == n { print $c }'
}
