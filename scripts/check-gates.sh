#!/usr/bin/env bash
#
# check-gates.sh — assert that every gate in scripts/ is actually run by CI.
#
# This is one half of the gate-conformance question. The other half — can the
# gate reject, and does it accept a clean tree — is asserted BEHAVIOURALLY by
# scripts/check-positive-controls.sh, which runs each gate against this tree.
#
# Capability is not asserted here, because it cannot be asserted by reading. A
# check that a gate DECLARES a self_test is satisfied just as well by
# `self_test() { :; }` as by one that proves something — a floor that reads source
# can be satisfied by prose or by an empty body, and only a floor that runs the
# gate cannot. What remains here is a question about CI configuration, which is
# genuinely a text question.
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

  # The contributor-checklist half uses the same matcher, so one control covers
  # both: a name present is found, a name absent is not.
  printf 'Run `bash scripts/wired.sh` before opening a PR.
' >"$tmp/CONTRIBUTING.md"
  grep -qF "scripts/wired.sh" "$tmp/CONTRIBUTING.md" ||
    self_test_die "a gate named in a checklist was not found in it"
  if grep -qF "scripts/absent.sh" "$tmp/CONTRIBUTING.md"; then
    self_test_die "a gate the checklist does not name was found in it"
  fi

  # An empty workflow directory means nothing is wired, not that everything is.
  mkdir -p "$tmp/empty"
  ! workflow_runs "wired.sh" "$tmp/empty" 2>/dev/null ||
    self_test_die "reported a gate as wired against a directory with no workflows"

  echo "check-gates self-test passed: it rejects a commented-out run step, an unmentioned gate, an empty workflow directory, and a gate missing from the contributor checklist."
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

# ─── the contributor checklist must name every gate CI runs ───
#
# A contributor who runs everything CONTRIBUTING.md lists and still fails CI has
# been given a checklist that does not do its job, and the omission is invisible
# from either document alone. The checklist drifted this way once already: it
# named five gates while CI ran seven.
#
# CONTRIBUTING is read raw. A gate named only inside a fenced block is still
# named to the reader, and stripping comments from markdown would strip nothing.
for script in scripts/*.sh; do
  name="$(basename "$script")"
  if ! grep -qF "scripts/${name}" CONTRIBUTING.md; then
    echo "::error::${name} is run by CI and is not named in CONTRIBUTING.md; a contributor following the checklist would fail on it" >&2
    fail=1
  fi
done

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
printf 'ok: %s gate script(s) run by CI and named in CONTRIBUTING.md (capability proven separately by check-positive-controls.sh)\n' "$checked"
