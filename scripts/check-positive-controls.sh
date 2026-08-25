#!/usr/bin/env bash
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
lib_dir="${repo_root}/scripts/lib"
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

  echo "check-positive-controls self-test passed: it rejects a no-op mutation, an off-target edit, and a pre-existing marker."
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
run_control() {
  local gate="$1" description="$2" target="$3" writer="$4" marker="$5"
  local before after

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
  if ! bash "$gate" >/dev/null 2>&1; then
    echo "::error::$(basename "$gate") rejects the unmodified tree; a gate that rejects everything proves as little as one that rejects nothing" >&2
    fail=1
    return
  fi

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

  if bash "$gate" >/dev/null 2>&1; then
    echo "::error::$(basename "$gate") passed with ${description} present in ${target}; the gate does not catch what it exists to catch" >&2
    fail=1
  else
    printf '  ok  %-30s accepts the clean tree, rejects %s\n' "$(basename "$gate")" "$description"
  fi
  unmutate "$target"
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
}

run_control scripts/check-context.sh \
  "a detached context masked by a trailing comment" \
  "$CONTEXT_TARGET" plant_detached_context \
  "positiveControlZzctl01Ctx"

run_control scripts/coverage.sh \
  "a floor the package cannot meet" \
  "$FLOORS_TARGET" plant_unmeetable_floor \
  "zzctl02floor"

run_control scripts/check-version-pins.sh \
  "a version pin nothing watches" \
  "$PINS_TARGET" plant_unwatched_pin \
  "zzctl03pin"

run_control scripts/check-release-urls.sh \
  "a download URL naming an asset goreleaser never produces" \
  "$URLS_TARGET" plant_wrong_download_url \
  "zzctl04url"

DOCPATH_TARGET="README.md"
plant_unresolvable_path() {
  printf '\n<!-- positive control -->\nSee `internal/zzctl06path/absent.go` for details.\n' >>"$DOCPATH_TARGET"
}

run_control scripts/check-doc-paths.sh \
  "prose naming a file that does not exist" \
  "$DOCPATH_TARGET" plant_unresolvable_path \
  "zzctl06path"

run_control scripts/check-gates.sh \
  "a gate script no workflow runs" \
  "$GATES_TARGET" plant_unwired_gate \
  "zzctl05gate"

# ─── the anti-vacuity floor ───
#
# Every gate carries a control and every control names a live gate. Without this
# the suite shrinks silently: a gate added without a control is a gate nothing
# proves, and it reads identically to one that is proven.
self="$(basename "${BASH_SOURCE[0]}")"
for script in scripts/*.sh; do
  name="$(basename "$script")"
  [ "$name" = "$self" ] && continue
  # The planted gate is a fixture of this run, not a gate of the repo.
  [ "$name" = "$(basename "$GATES_TARGET")" ] && continue
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
