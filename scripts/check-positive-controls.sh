#!/usr/bin/env bash
# shellcheck disable=SC2016  # single-quoted $ here belongs to awk and printf, not the shell
#
# check-positive-controls.sh — mutate the real tree, one violation per gate, and
# require the gate to reject it.
#
# A gate's own self-test drives it against fixtures. This drives it against THIS
# repository: it introduces the exact violation the gate exists to catch into the
# working tree, runs the gate, and requires a non-zero exit. The two catch
# different things. A self-test proves the matching logic works on a synthetic
# input; a control proves the gate is wired to the tree it is supposed to guard —
# that the paths it scans are the paths that exist, and that CI runs the thing
# being proven rather than something adjacent to it.
#
# This is also the anti-vacuity floor for the gate suite, and it is a BEHAVIOURAL
# floor rather than a textual one. A floor that decides whether a gate is proven
# by reading source can be satisfied by prose — by a `self_test() { :; }` with an
# empty body, or by a comment saying the controls were removed. This one records
# a gate as covered only when `run_control` actually executed against it, so the
# only way to be counted is to have been run.
#
# Both halves are observed, because a gate that rejects everything is exactly as
# useless as one that rejects nothing and either half alone passes a one-sided
# check:
#
#   ACCEPTS A CLEAN TREE — asserted before every mutation.
#   REJECTS ITS VIOLATION — asserted after it.
#
# Four properties make it hold, and each has been the failure at least once:
#
#   ANTI-VACUITY FLOOR. A gate with no control fails this run, and a control
#   naming a gate that no longer exists fails it too. The suite cannot quietly
#   shrink to the gates someone remembered.
#
#   CLEAN BEFORE MUTATING. Each control asserts the gate passes on the unmodified
#   tree first. Without that, a non-zero exit after the mutation proves nothing —
#   the gate may have been red the whole time for an unrelated reason, and the
#   control would report success for a gate that cannot distinguish anything.
#
#   RESTORED AFTER. Every mutation is undone whether the control passes, fails,
#   or the script is interrupted, so a failed run does not leave the tree dirty.
#
# Usage: scripts/check-positive-controls.sh

set -euo pipefail



repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

backup_dir="$(mktemp -d)"
mutated=()

restore_all() {
  local relative
  for relative in "${mutated[@]:-}"; do
    [ -n "$relative" ] || continue
    if [ -f "${backup_dir}/$(printf '%s' "$relative" | tr '/' '_')" ]; then
      cp "${backup_dir}/$(printf '%s' "$relative" | tr '/' '_')" "$relative"
    else
      rm -f "$relative"
    fi
  done
  rm -rf "$backup_dir"
}
trap restore_all EXIT

# mutate records a file's original content (or its absence) so restore_all can
# put it back, then leaves the caller to write the violation.
mutate() {
  local relative="$1"
  mutated+=("$relative")
  if [ -f "$relative" ]; then
    cp "$relative" "${backup_dir}/$(printf '%s' "$relative" | tr '/' '_')"
  fi
}

# unmutate_since restores every file mutated after index $1 and forgets them.
unmutate_since() {
  local from="$1" i
  for ((i = ${#mutated[@]} - 1; i >= from; i--)); do
    unmutate "${mutated[i]}"
    unset 'mutated[i]'
  done
  mutated=("${mutated[@]}")
}

unmutate() {
  local relative="$1" saved
  saved="${backup_dir}/$(printf '%s' "$relative" | tr '/' '_')"
  if [ -f "$saved" ]; then
    cp "$saved" "$relative"
  else
    rm -f "$relative"
  fi
}

# mutation_landed decides whether a mutation actually took. Three conditions,
# and every one of them has been the hole:
#
#   ABSENT BEFORE. The marker must not already be in the target. This is the
#   condition that is easy to skip and that quietly voids the other two: a marker
#   made of realistic syntax tends to be somewhere in the tree already — often in
#   the documentation of the very gate whose violation it imitates — and then
#   present-after proves nothing at all. Hence the markers below are synthetic
#   tokens that appear nowhere but in a mutation.
#
#   CHANGED. The file must differ, so an edit that no-opped is caught rather than
#   handing the gate an unmodified file whose correct pass gets recorded as proof
#   the control worked.
#
#   PRESENT AFTER. The marker must be there, so a change that landed somewhere
#   other than intended is caught too.
mutation_landed() {
  local before="$1" after="$2" marker="$3"
  ! printf '%s\n' "$before" | grep -qF -- "$marker" || return 1
  [ "$before" != "$after" ] || return 1
  printf '%s\n' "$after" | grep -qF -- "$marker" || return 1
  return 0
}


# CRASH_INDICATORS are the shapes an uncontrolled failure leaves in output. A
# crash exits non-zero, so a floor reading exit status alone records it as a
# rejection — exit-code-conflates-causes, occurring inside the thing built to
# check for it.
#
# Naming the mutation does not close this on its own: a gate can crash while
# processing the planted file and print its name on the way down, which reads as
# a clean catch under both rules at once. That case is this script's own control.
CRASH_INDICATORS=(
  "No such file or directory"
  "command not found"
  "unbound variable"
  "syntax error"
  "Traceback (most recent call last)"
  "panic:"
  "Segmentation fault"
)

# controlled_rejection reports whether output is a verdict the gate reached and
# printed, rather than a failure it fell out of.
#
# THE CONTRACT, not a vocabulary guess: every gate in scripts/ ends a rejection
# with `== <what> NOT met ==`, or with `<gate> self-test FAILED: <reason>` when it
# could not establish its own trustworthiness. Broadening this pattern until it
# matches whatever the gates happen to print would defeat it — the point is that
# reaching the line is the evidence.
#
# Both halves are needed. Absence of a crash indicator does not prove the gate
# got to its own conclusion, and a verdict line printed before a later crash does
# not prove it finished — so the output must carry a verdict AND no crash.
#
# TWO RULES, AND THE NUMBER COMES FIRST.
#
# A status of 126 or 127 means the shell could not execute something: a missing
# interpreter, a vanished binary. A gate that exits that way evaluated nothing.
# The text rule cannot see the worst shape of this — a gate that exits 127 having
# printed NOTHING carries no indicator to match, and a floor screening only text
# records it as the strictest gate in the suite. The number is the only thing
# left to read.
#
# The text rule stays for the shape the number cannot see: a gate that died
# mid-run, said so, and exited 1 like an ordinary rejection.
#
# ORDER MATTERS BETWEEN THEM. A gate whose own verdict QUOTES a diagnostic — the
# portability gate reports `mapfile: command not found` as its finding — reaches a
# verdict and prints it. Letting a text indicator veto a printed verdict marks a
# working gate as crashed, so the verdict is checked before the text and the text
# only decides cases where no verdict was reached.
controlled_rejection() {
  local output="$1" status="${2:-1}" indicator

  # The number, first, because a silent crash has nothing else to read.
  case "$status" in
    126 | 127)
      return 1
      ;;
  esac

  if printf '%s\n' "$output" | grep -qE '^(== .* NOT met ==|[a-z-]+ self-test FAILED: )'; then
    return 0
  fi

  # No verdict. Whether it crashed or merely exited quietly, it is not a catch —
  # the indicators below only sharpen the message.
  for indicator in "${CRASH_INDICATORS[@]}"; do
    if printf '%s\n' "$output" | grep -qF -- "$indicator"; then
      return 1
    fi
  done
  return 1
}

# ── Why this script self-tests ────────────────────────────────────────────────
#
# It is the proof that every other gate can reject, so a false pass here retires
# the evidence behind all of them at once. The specific hazard is that a control
# whose mutation silently no-ops records the gate's correct pass as proof the
# control worked — a failure in the safe-looking direction, which reading will
# not catch.
self_test_die() {
  echo "check-positive-controls self-test FAILED: $*" >&2
  echo "The controls could not be shown to detect a no-op mutation, so their results are not evidence." >&2
  exit 1
}

self_test() {
  # A mutation that changed the file and planted the marker.
  mutation_landed "before" "before + violation" "violation" ||
    self_test_die "rejected a mutation that changed the file and planted its marker"

  # A mutation that no-opped. This is the rackctl case: a sed range BSD does not
  # implement, a pattern spanning a character the file lacks. The file is
  # unchanged and the gate then correctly passes it.
  ! mutation_landed "before" "before" "violation" ||
    self_test_die "accepted a mutation that left the file unchanged"

  # A mutation that changed the file but did not introduce the violation.
  ! mutation_landed "before" "before + unrelated edit" "violation" ||
    self_test_die "accepted a change that did not plant the violation"

  # A marker already present before the writer ran proves nothing on its own, so
  # the change check has to be the one that fails here.
  ! mutation_landed "violation" "violation" "violation" ||
    self_test_die "accepted an unchanged file because the marker happened to be in it already"

  # ── the case that defeats exit-status AND name-the-mutation together ──
  #
  # A gate that accepts the clean tree, then crashes only on the bad fixture with
  # a message naming the planted file, satisfies both rules while proving
  # nothing. It exits non-zero and its output names the mutation, so a floor
  # checking only those two records a clean catch. This is that gate.
  local crashing clean_verdict
  crashing='check-probe self-test passed.
processing internal/zzctl06path/absent.go
cat: /nonexistent/zzctl06path: No such file or directory'
  ! controlled_rejection "$crashing" ||
    self_test_die "accepted a crash as a rejection; it names the mutation and exits non-zero, which is exactly why exit status and naming are not enough on their own"

  # A gate that reached its own verdict is a rejection.
  clean_verdict='::error::README.md:1: names `nope.go`, which does not exist
== documented paths NOT met =='
  controlled_rejection "$clean_verdict" ||
    self_test_die "rejected a real verdict as a crash"

  # A self-test failure is a controlled outcome too: the gate established it
  # could not be trusted and said so, which is not the same as falling over.
  controlled_rejection 'check-probe self-test FAILED: the detector could not produce a positive' ||
    self_test_die "rejected a self-test failure as a crash"

  # Non-zero with neither a verdict nor a crash indicator is still not a verdict.
  ! controlled_rejection 'something went wrong' ||
    self_test_die "accepted output carrying no verdict line as a rejection"

  # ── the shape a text rule cannot see ──
  #
  # A gate whose interpreter or tool has vanished exits 127 having evaluated
  # nothing, and it may print NOTHING on the way out. There is no indicator to
  # match, so a floor screening only text scores it as the strictest gate in the
  # suite. Only the number is left.
  local silent_tmp silent_out silent_status
  silent_tmp="$(mktemp -d)"
  printf '#!/usr/bin/env bash\nexit 127\n' >"$silent_tmp/silent127.sh"
  silent_status=0
  silent_out="$(bash "$silent_tmp/silent127.sh" 2>&1)" || silent_status=$?

  # The control must still be the case it exists for. A fixture that starts
  # printing, or stops exiting 127, silently stops testing a silent 127.
  [ "$silent_status" -eq 127 ] ||
    self_test_die "the silent-crash control exited ${silent_status}, not 127; it no longer constructs the case it exists for"
  [ -z "$silent_out" ] ||
    self_test_die "the silent-crash control printed output, so it now tests the text rule rather than the numeric one: ${silent_out}"

  ! controlled_rejection "$silent_out" "$silent_status" ||
    self_test_die "scored a silent exit 127 as a rejection; a gate whose tool vanished evaluated nothing and read as the strictest gate in the suite"
  ! controlled_rejection "cannot execute: No such file or directory" 127 ||
    self_test_die "scored an exit 127 as a rejection even with a crash message present"
  rm -rf "$silent_tmp"

  # A gate whose own VERDICT quotes a diagnostic has reached a verdict. Letting a
  # text indicator veto a printed verdict marks a working gate as crashed.
  controlled_rejection "$(printf '::error::x uses mapfile: command not found\n== shell portability NOT met ==\n')" 1 ||
    self_test_die "a printed verdict was vetoed because the finding it reports quotes a shell diagnostic"

  echo "check-positive-controls self-test passed: it rejects a no-op mutation, an off-target edit, a pre-existing marker, a crash that names the mutation, a non-zero exit with no verdict, a SILENT exit 127, and a real verdict that quotes a shell diagnostic."
}

self_test

fail=0
controlled=()

# run_control drives one gate through clean → mutate → VERIFY THE MUTATION →
# reject → restore.
#
# The verification step is the one that is easy to leave out and impossible to
# spot by reading. A mutation that silently fails to land — a sed address range
# BSD does not implement, a pattern spanning a character the file does not
# contain, a floor the package already meets — hands the gate an unmutated
# fixture. The gate correctly passes it, and the run records that pass as proof
# the control works. It fails in the safe-looking direction.
#
# So the mutated text is inspected rather than the verdict: the file must have
# changed, and it must now contain the marker the writer claims to have planted.
#
#   $1 gate script path
#   $2 human description of the violation introduced
#   $3 file the control mutates
#   $4 a function that writes the violation into $3
#   $5 a literal string that must appear in $3 afterwards
#   $6 a literal string the gate's REJECTION must contain
run_control() {
  local gate="$1" description="$2" target="$3" writer="$4" marker="$5" names="$6"
  local before after rejection rejection_status mutated_before indicator

  # A writer may touch more than the primary target — a fixture that trips TWO
  # rules proves nothing about either, because the gate rejects for whichever it
  # reaches first, so a writer sometimes has to satisfy one rule in order to
  # isolate the other. Everything it touched is restored, not just $3.
  mutated_before=${#mutated[@]}

  if [ ! -f "$gate" ]; then
    echo "::error::a positive control names ${gate}, which does not exist" >&2
    fail=1
    return
  fi
  controlled+=("$(basename "$gate")")

  # Clean before mutating. Without this a non-zero exit after the mutation proves
  # nothing: the gate may have been failing the whole time for an unrelated
  # reason, and the control would report success for a gate that distinguishes
  # nothing.
  # ACCEPTS A CLEAN TREE. Without this a non-zero exit after the mutation proves
  # nothing: the gate may have been failing the whole time for an unrelated
  # reason, and a gate that rejects everything distinguishes nothing.
  local clean
  if ! clean=$(bash "$gate" 2>&1); then
    echo "::error::$(basename "$gate") rejects the unmodified tree; a gate that rejects everything proves as little as one that rejects nothing" >&2
    fail=1
    return
  fi
  # A gate can exit 0 having crashed in a subshell whose status was swallowed.
  for indicator in "${CRASH_INDICATORS[@]}"; do
    if printf '%s\n' "$clean" | grep -qF -- "$indicator"; then
      echo "::error::$(basename "$gate") accepted the unmodified tree with a crash indicator in its output (${indicator}); its pass is not a verdict" >&2
      fail=1
      return
    fi
  done

  before=""
  [ -f "$target" ] && before="$(cat "$target")"

  mutate "$target"
  "$writer"

  after=""
  [ -f "$target" ] && after="$(cat "$target")"

  if ! mutation_landed "$before" "$after" "$marker"; then
    echo "::error::the control for $(basename "$gate") did not land its mutation in ${target} (marker ${marker} must be absent before and present after); whatever the gate says next is about a file that does not carry the violation" >&2
    fail=1
    unmutate "$target"
    return
  fi

  rejection_status=0
  rejection=$(bash "$gate" 2>&1) || rejection_status=$?
  if [ "$rejection_status" -eq 0 ]; then
    echo "::error::$(basename "$gate") passed with ${description} present in ${target}; the gate does not catch what it exists to catch" >&2
    fail=1
    unmutate_since "$mutated_before"
    return
  fi

  # THE REJECTION MUST BE A VERDICT, NOT A CRASH.
  #
  # Checked before the naming rule, because a gate that crashes while processing
  # the planted file prints its name on the way down and satisfies that rule
  # while proving nothing.
  if ! controlled_rejection "$rejection" "$rejection_status"; then
    echo "::error::$(basename "$gate") exited ${rejection_status} without reaching a verdict — it crashed rather than rejecting, and a crash is not a catch" >&2
    printf '%s\n' "$rejection" | sed 's/^/    /' >&2
    fail=1
    unmutate_since "$mutated_before"
    return
  fi

  # THE REJECTION MUST NAME WHAT WAS PLANTED.
  #
  # A non-zero exit alone is not proof the gate found the violation: a gate can
  # reject a mutated tree for an unrelated reason — its own self-test breaking,
  # a second rule the fixture happens to trip — and a floor reading only the exit
  # status scores that as a catch. Requiring the rejection to name the planted
  # thing is what closes the gap between "it failed" and "it found what I
  # planted".
  if ! printf '%s\n' "$rejection" | grep -qF -- "$names"; then
    echo "::error::$(basename "$gate") rejected the mutated tree without naming ${names}; it failed for some other reason and this control proves nothing about ${description}" >&2
    printf '%s\n' "$rejection" | sed 's/^/    /' >&2
    fail=1
    unmutate_since "$mutated_before"
    return
  fi

  printf '  ok  %-30s accepts the clean tree, rejects %s (naming it)\n' "$(basename "$gate")" "$description"
  unmutate_since "$mutated_before"
}

# ─── the controls ───

CONTEXT_TARGET="internal/cloud/aws/positive_control.go"
plant_detached_context() {
  cat >"$CONTEXT_TARGET" <<'GO'
package aws

import "context"

// A detached context whose line also mentions the one allowed bootstrap. The
// exclusion used to read that comment and filter this out.
func positiveControlZzctl01Ctx() context.Context {
	return context.Background() // not signal.NotifyContext(context.Background()
}
GO
}

FLOORS_TARGET=".coverage-floors"
plant_unmeetable_floor() {
  # cmd is the lowest-covered package in the tree, so a 100 floor on it is
  # unmeetable by construction rather than by a number that might drift up to
  # meet it. A floor a package already satisfies is not a mutation.
  # The synthetic token rides in the trailing comment, which the gate strips
  # before reading the floor — so the floor is exactly `package cmd 100` while
  # the marker is unique to this control. `package cmd` on its own would not do:
  # it is already in this file, so present-after would pass on a no-op append.
  printf '\npackage cmd                        100  # zzctl02floor\n' >>"$FLOORS_TARGET"
}

PINS_TARGET=".github/workflows/positive-control.yml"
plant_unwatched_pin() {
  cat >"$PINS_TARGET" <<'YML'
name: positive-control
on: workflow_dispatch
jobs:
  probe:
    runs-on: ubuntu-latest
    steps:
      - run: |
          go install example.com/zzctl03pin@v9.9.9
YML
}

URLS_TARGET="README.md"
plant_wrong_download_url() {
  printf '\n<!-- positive control -->\n```sh\ncurl -LO https://github.com/nanohype/cloudgov/releases/latest/download/cloudgov_Darwin_zzctl04url_arm64.tar.gz\n```\n' >>"$URLS_TARGET"
}

GATES_TARGET="scripts/positive-control-gate.sh"
plant_unwired_gate() {
  cat >"$GATES_TARGET" <<'SH'
#!/usr/bin/env bash
# A gate no workflow runs. It would report green locally and guard nothing on a
# pull request, which is the state check-gates.sh exists to catch.
echo "zzctl05gate: checking nothing"
SH
  chmod +x "$GATES_TARGET"

  # check-gates enforces two rules over the same population: every gate is run by
  # a workflow, and every gate is named in the contributor checklist. A plant
  # tripping both would be rejected for whichever is checked first, and this
  # control would prove nothing about either. Satisfying the checklist rule
  # isolates the wiring one.
  mutate CONTRIBUTING.md
  printf '\n<!-- positive control -->\nRun `bash scripts/positive-control-gate.sh` too.\n' >>CONTRIBUTING.md
}

CHECKLIST_TARGET="scripts/positive-control-listed.sh"
plant_unlisted_gate() {
  cat >"$CHECKLIST_TARGET" <<'SH'
#!/usr/bin/env bash
# A gate CI runs and the contributor checklist omits: a contributor following
# CONTRIBUTING.md runs everything it lists and still fails on this one.
echo "zzctl07list: checking nothing"
SH
  chmod +x "$CHECKLIST_TARGET"

  # The mirror image: wire it so only the checklist rule can trip.
  mutate .github/workflows/ci.yml
  printf '\n      - name: positive control\n        run: bash scripts/positive-control-listed.sh\n' >>.github/workflows/ci.yml
}

run_control scripts/check-context.sh \
  "a detached context masked by a trailing comment" \
  "$CONTEXT_TARGET" plant_detached_context \
  "positiveControlZzctl01Ctx" \
  "positive_control.go"

run_control scripts/coverage.sh \
  "a floor the package cannot meet" \
  "$FLOORS_TARGET" plant_unmeetable_floor \
  "zzctl02floor" \
  "below its 100% floor"

run_control scripts/check-version-pins.sh \
  "a version pin nothing watches" \
  "$PINS_TARGET" plant_unwatched_pin \
  "zzctl03pin" \
  "zzctl03pin"

run_control scripts/check-release-urls.sh \
  "a download URL naming an asset goreleaser never produces" \
  "$URLS_TARGET" plant_wrong_download_url \
  "zzctl04url" \
  "zzctl04url"

DOCPATH_TARGET="README.md"
plant_unresolvable_path() {
  printf '\n<!-- positive control -->\nSee `internal/zzctl06path/absent.go` for details.\n' >>"$DOCPATH_TARGET"
}

run_control scripts/check-doc-paths.sh \
  "prose naming a file that does not exist" \
  "$DOCPATH_TARGET" plant_unresolvable_path \
  "zzctl06path" \
  "zzctl06path"

run_control scripts/check-gates.sh \
  "a gate script no workflow runs" \
  "$GATES_TARGET" plant_unwired_gate \
  "zzctl05gate" \
  "is not run by any workflow"

PORT_TARGET="scripts/positive-control-bash4.sh"
plant_bash4_construct() {
  # A bash 4 builtin. Under a macOS system bash this is not a parse error — it is
  # a command that does not exist, so the script starts, runs, and aborts at this
  # line having reported on nothing.
  cat >"$PORT_TARGET" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
zzctl08port=()
mapfile -t zzctl08port < /dev/null
echo "${#zzctl08port[@]}"
SH
  chmod +x "$PORT_TARGET"
}

run_control scripts/check-shell-portability.sh \
  "a gate needing a bash newer than a macOS system bash" \
  "$PORT_TARGET" plant_bash4_construct \
  "zzctl08port" \
  "positive-control-bash4.sh"

run_control scripts/check-gates.sh \
  "a gate script the contributor checklist omits" \
  "$CHECKLIST_TARGET" plant_unlisted_gate \
  "zzctl07list" \
  "not named in CONTRIBUTING.md"


self="$(basename "${BASH_SOURCE[0]}")"

# ─── the controls: a gate's own dependencies ───
#
# The controls above plant a violation in the TREE. They cannot reach a different
# failure entirely: the gate's helper breaking, rather than the tree being wrong.
#
# That failure is silent by construction. A helper's status is read by its caller
# — `out=$(scan x) || die` — and bash suppresses errexit through the whole left
# side of that test, so a command failing inside the helper does not abort it.
# The helper returns nothing, and nothing is what a clean file also produces. A
# stripper that cannot read a file yields a file with no findings in it.
#
# So each gate is run once more against a deliberately broken dependency, and is
# required to REJECT rather than to report a clean tree. The stub names itself on
# stderr, so the rejection can be required to name what was broken — a gate that
# happens to fail for its own unrelated reason does not count as catching this.
dependency_controlled=()

run_dependency_control() {
  local gate="$1" lib="$2" marker="$3"
  local clean rejection rejection_status mutated_before

  if [ ! -f "$gate" ] || [ ! -f "$lib" ]; then
    echo "::error::a dependency control names ${gate} and ${lib}; one of them does not exist" >&2
    fail=1
    return
  fi

  if ! clean=$(bash "$gate" 2>&1); then
    echo "::error::$(basename "$gate") rejects the unmodified tree; its behaviour against a broken ${lib} would prove nothing" >&2
    fail=1
    return
  fi

  mutated_before=${#mutated[@]}
  mutate "$lib"
  # A helper that refuses to run, written in the language its callers invoke it
  # as: an awk program replaced by python is a syntax error rather than a clean
  # refusal, and the two fail differently. Exit 3 rather than 1, because 1 is
  # what several of these tools return for "no match" — an answer, not a failure.
  case "$lib" in
    *.awk)
      cat >"$lib" <<AWK
BEGIN { print "${marker}" > "/dev/stderr"; exit 3 }
AWK
      ;;
    *.py)
      cat >"$lib" <<PY
import sys
sys.stderr.write("${marker}\n")
raise SystemExit(3)
PY
      ;;
    *)
      echo "::error::a dependency control names ${lib}, whose language this control cannot stub" >&2
      fail=1
      unmutate_since "$mutated_before"
      return
      ;;
  esac

  if ! grep -qF -- "$marker" "$lib"; then
    echo "::error::the dependency control did not land its stub in ${lib}; whatever the gate says next is about the real library" >&2
    fail=1
    unmutate_since "$mutated_before"
    return
  fi

  rejection_status=0
  rejection=$(bash "$gate" 2>&1) || rejection_status=$?
  if [ "$rejection_status" -eq 0 ]; then
    echo "::error::$(basename "$gate") passed with ${lib} unable to run; it reported a clean tree it could not read" >&2
    fail=1
    unmutate_since "$mutated_before"
    return
  fi

  if ! controlled_rejection "$rejection" "$rejection_status"; then
    echo "::error::$(basename "$gate") exited ${rejection_status} against a broken ${lib} without reaching a verdict; a crash is not a catch" >&2
    printf '%s\n' "$rejection" | sed 's/^/    /' >&2
    fail=1
    unmutate_since "$mutated_before"
    return
  fi

  if ! printf '%s\n' "$rejection" | grep -qF -- "$marker"; then
    echo "::error::$(basename "$gate") rejected without the broken ${lib} naming itself in the output; it failed for some other reason and this control proves nothing" >&2
    printf '%s\n' "$rejection" | sed 's/^/    /' >&2
    fail=1
    unmutate_since "$mutated_before"
    return
  fi

  dependency_controlled+=("$(basename "$gate")")
  printf '  ok  %-30s rejects rather than passing when %s cannot run\n' "$(basename "$gate")" "$(basename "$lib")"
  unmutate_since "$mutated_before"
}

run_dependency_control scripts/check-context.sh \
  scripts/lib/strip-comments.awk zzdep01strip

run_dependency_control scripts/check-version-pins.sh \
  scripts/lib/strip-comments.awk zzdep02strip

run_dependency_control scripts/check-gates.sh \
  scripts/lib/strip-comments.awk zzdep03strip

run_dependency_control scripts/check-release-urls.sh \
  scripts/lib/goreleaser-assets.py zzdep04assets

run_dependency_control scripts/check-shell-portability.sh \
  scripts/lib/strip-comments.awk zzdep05strip

# Every gate that reads a shared library must be controlled against that library
# failing. A gate added with a new `${lib_dir}` reference and no control here is
# a gate whose helper can break silently.
for script in scripts/*.sh; do
  name="$(basename "$script")"
  [ "$name" = "$self" ] && continue
  [ "$name" = "$(basename "$GATES_TARGET")" ] && continue
  [ "$name" = "$(basename "$CHECKLIST_TARGET")" ] && continue
  [ "$name" = "$(basename "$PORT_TARGET")" ] && continue
  grep -q 'lib_dir' "$script" || continue
  covered=0
  for controlled_name in "${dependency_controlled[@]:-}"; do
    [ "$controlled_name" = "$name" ] && covered=1
  done
  if [ "$covered" -eq 0 ]; then
    echo "::error::${name} reads a shared library and has no dependency control; nothing proves it rejects when that library cannot run" >&2
    fail=1
  fi
done

# ─── the anti-vacuity floor ───
#
# Every gate carries a control and every control names a live gate. Without this
# the suite shrinks silently: a gate added without a control is a gate nothing
# proves, and it reads identically to one that is proven.
for script in scripts/*.sh; do
  name="$(basename "$script")"
  [ "$name" = "$self" ] && continue
  # The planted gate is a fixture of this run, not a gate of the repo.
  [ "$name" = "$(basename "$GATES_TARGET")" ] && continue
  [ "$name" = "$(basename "$CHECKLIST_TARGET")" ] && continue
  [ "$name" = "$(basename "$PORT_TARGET")" ] && continue
  covered=0
  for controlled_name in "${controlled[@]:-}"; do
    [ "$controlled_name" = "$name" ] && covered=1
  done
  if [ "$covered" -eq 0 ]; then
    echo "::error::${name} is a gate with no positive control; nothing proves it can reject" >&2
    fail=1
  fi
done

if [ "${#controlled[@]}" -eq 0 ]; then
  echo "error: no controls ran — the suite is empty, which is not a pass." >&2
  exit 2
fi

if [ "$fail" -ne 0 ]; then
  echo "== positive controls NOT met =="
  exit 1
fi
printf 'ok: %s gate(s) each accepted the clean tree and rejected its own violation, every mutation verified by inspection\n' "${#controlled[@]}"
