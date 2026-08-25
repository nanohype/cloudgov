#!/usr/bin/env bash
#
# check-gates.sh — assert that every gate in scripts/ is actually run by CI.
#
# This is one half of the gate-conformance question. The other half — can the
# gate reject, and does it accept a clean tree — is asserted BEHAVIOURALLY by
# scripts/check-positive-controls.sh, which runs each gate against this tree.
#
# The split is deliberate, and it is a correction. This script used to also check
# that each gate declared and called a `self_test` function, by matching its
# source text. That check fails open in the way every text-based floor does: a
# `self_test() { :; }` that does nothing satisfies it exactly as well as one that
# proves anything. A floor that reads source can be satisfied by prose or by an
# empty body; a floor that runs the gate cannot. So the capability half moved to
# where it can be observed rather than read, and what is left here is a question
# about CI configuration, which is genuinely a text question.
#
# Even here the text is read with comments stripped: a commented-out `run:` step
# is not a step, and a gate "run" only by a comment is a gate CI never executes.
#
# Usage: scripts/check-gates.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lib_dir="${repo_root}/scripts/lib"
cd "$repo_root"

self="$(basename "${BASH_SOURCE[0]}")"

# workflow_runs reports whether any workflow in $2 executes the script named $1.
#
# Comments are stripped first. A workflow carrying `# run: bash scripts/x.sh`
# documents an intention; it does not run anything.
workflow_runs() {
  local name="$1" workflows="$2" file
  for file in "$workflows"/*.yml "$workflows"/*.yaml; do
    [ -f "$file" ] || continue
    if awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$file" | grep -qF "scripts/${name}"; then
      return 0
    fi
  done
  return 1
}

# ── Why this script self-tests ────────────────────────────────────────────────
#
# Its one check is a grep over YAML, which is the shape that silently matches
# nothing when a path convention changes — and reports that as every gate being
# wired.
self_test_die() {
  echo "check-gates self-test FAILED: $*" >&2
  echo "The gate could not be shown to reject, so its pass is not evidence." >&2
  exit 1
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/workflows"

  cat >"$tmp/workflows/ci.yml" <<'WF'
jobs:
  build:
    steps:
      - run: bash scripts/wired.sh
      # - run: bash scripts/commented.sh
WF

  workflow_runs "wired.sh" "$tmp/workflows" ||
    self_test_die "reported a gate that CI runs as unwired"

  ! workflow_runs "commented.sh" "$tmp/workflows" 2>/dev/null ||
    self_test_die "counted a commented-out run step as CI running the gate"

  ! workflow_runs "absent.sh" "$tmp/workflows" 2>/dev/null ||
    self_test_die "reported a gate no workflow mentions as wired"

  # An empty workflow directory means nothing is wired, not that everything is.
  mkdir -p "$tmp/empty"
  ! workflow_runs "wired.sh" "$tmp/empty" 2>/dev/null ||
    self_test_die "reported a gate as wired against a directory with no workflows"

  echo "check-gates self-test passed: it rejects a commented-out run step, an unmentioned gate, and an empty workflow directory."
}

self_test

fail=0
checked=0
for script in scripts/*.sh; do
  name="$(basename "$script")"
  [ "$name" = "$self" ] && continue
  checked=$((checked + 1))
  if ! workflow_runs "$name" ".github/workflows"; then
    echo "::error::${name} is not run by any workflow; it guards nothing on a pull request" >&2
    fail=1
  fi
done

# This script is a gate too, and a gate nothing runs is the case it exists for.
if ! workflow_runs "$self" ".github/workflows"; then
  echo "::error::${self} is not run by any workflow; the wiring check itself is unwired" >&2
  fail=1
fi

# A verdict over nothing is not a pass: an empty scripts/ directory, or a glob
# that stopped matching, would otherwise report every gate as wired.
if [ "$checked" -eq 0 ]; then
  echo "error: no gate scripts found in scripts/ — the enumeration is broken, not the tree." >&2
  exit 2
fi

if [ "$fail" -ne 0 ]; then
  echo "== gate wiring NOT met =="
  exit 1
fi
printf 'ok: %s gate script(s) run by CI (capability proven separately by check-positive-controls.sh)\n' "$checked"
