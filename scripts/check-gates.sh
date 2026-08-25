#!/usr/bin/env bash
#
# check-gates.sh — assert that every gate in scripts/ can be shown to reject, and
# that CI actually runs it.
#
# A check that cannot fail reports success exactly as loudly as one that can, and
# it is cited the same way afterwards. Both halves have to hold and they break
# independently: a gate whose self-test nothing invokes rots unnoticed, and a
# self-testing gate no workflow runs protects nothing. Checking one half and
# reporting on the gate is the failure this script exists to prevent.
#
# The invariant, over the population rather than a list:
#
#   every executable scripts/*.sh other than this one
#     declares a self_test function,
#     invokes it unconditionally on every run,
#     names the failure loudly enough to be found (self_test_die or equivalent),
#     and is invoked by at least one workflow in .github/workflows/.
#
# Self-tests run as part of the ordinary invocation rather than behind a flag, so
# there is no separate CI step for anyone to forget to add.
#
# Usage: scripts/check-gates.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lib_dir="${repo_root}/scripts/lib"
cd "$repo_root"

self="$(basename "${BASH_SOURCE[0]}")"

# audit_gate checks one script. Taking the script and the workflow directory as
# arguments is what lets the self-test drive it against fixtures.
#
# Exit: 0 conforms, 1 does not.
audit_gate() {
  local script="$1" workflows="$2"
  local name code fail=0
  name="$(basename "$script")"

  # Comments are stripped before matching for the declaration and the call. A
  # commented-out self_test is the exact state this check exists to catch — the
  # thing standing where the removed implementation should be IS a comment saying
  # so — and a matcher that reads comments as code goes green on it.
  #
  # String bodies are left intact: the failure-message check below looks for text
  # inside a string, which is the subject rather than a mention.
  code="$(awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$script")"

  if ! printf '%s\n' "$code" | grep -qE '^[[:space:]]*self_test\(\)[[:space:]]*\{'; then
    echo "::error::${name} declares no self_test function; nothing shows the gate can reject" >&2
    fail=1
  fi

  # Called at top level, not merely defined. A definition nothing invokes is the
  # rot this check is named after.
  if ! printf '%s\n' "$code" | grep -qE '^self_test$'; then
    echo "::error::${name} defines self_test but never calls it at top level" >&2
    fail=1
  fi

  # A self-test that fails silently is a self-test that passed. The message lives
  # in a string literal, so this one reads the code view too — a commented-out
  # message is not a message.
  if ! printf '%s\n' "$code" | grep -qE 'self.test.*FAILED'; then
    echo "::error::${name} has no failure message naming the self-test, so a broken gate reads as a clean one" >&2
    fail=1
  fi

  if ! grep -rqF "scripts/${name}" "$workflows"; then
    echo "::error::${name} is not run by any workflow in ${workflows}; its self-test never executes in CI" >&2
    fail=1
  fi

  return "$fail"
}

# ── Why this script self-tests ────────────────────────────────────────────────
#
# It is the gate over the gates, so a false pass here withdraws the guarantee
# from every check below it at once while still printing green.
self_test_die() {
  echo "check-gates self-test FAILED: $*" >&2
  echo "The gate could not be shown to reject, so its pass is not evidence." >&2
  exit 1
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/scripts" "$tmp/workflows"

  cat >"$tmp/workflows/ci.yml" <<'WF'
      - run: bash scripts/conformant.sh
      - run: bash scripts/silent.sh
      - run: bash scripts/uncalled.sh
      - run: bash scripts/no-selftest.sh
      - run: bash scripts/commented-out.sh
WF

  cat >"$tmp/scripts/conformant.sh" <<'OK'
self_test_die() { echo "conformant self-test FAILED: $*" >&2; exit 1; }
self_test() { :; }
self_test
OK
  audit_gate "$tmp/scripts/conformant.sh" "$tmp/workflows" ||
    self_test_die "rejected a script that self-tests and is run by CI"

  cat >"$tmp/scripts/uncalled.sh" <<'UNCALLED'
self_test_die() { echo "uncalled self-test FAILED: $*" >&2; exit 1; }
self_test() { :; }
UNCALLED
  ! audit_gate "$tmp/scripts/uncalled.sh" "$tmp/workflows" 2>/dev/null ||
    self_test_die "accepted a self_test that is defined but never invoked"

  cat >"$tmp/scripts/no-selftest.sh" <<'NONE'
echo "checking things"
NONE
  ! audit_gate "$tmp/scripts/no-selftest.sh" "$tmp/workflows" 2>/dev/null ||
    self_test_die "accepted a gate with no self_test at all"

  # A gate whose self_test was removed and replaced by a comment saying so. This
  # is the fail-open direction: a matcher reading comments as code accepts it.
  cat >"$tmp/scripts/commented-out.sh" <<'CO'
# self_test_die() { echo "commented-out self-test FAILED: $*" >&2; exit 1; }
# self_test() { :; }
# self_test
echo "checking things"
CO
  ! audit_gate "$tmp/scripts/commented-out.sh" "$tmp/workflows" 2>/dev/null ||
    self_test_die "accepted a gate whose self_test exists only as a comment"

  cat >"$tmp/scripts/silent.sh" <<'SILENT'
self_test() { :; }
self_test
SILENT
  ! audit_gate "$tmp/scripts/silent.sh" "$tmp/workflows" 2>/dev/null ||
    self_test_die "accepted a self-test with no failure message"

  cat >"$tmp/scripts/unrun.sh" <<'UNRUN'
self_test_die() { echo "unrun self-test FAILED: $*" >&2; exit 1; }
self_test() { :; }
self_test
UNRUN
  ! audit_gate "$tmp/scripts/unrun.sh" "$tmp/workflows" 2>/dev/null ||
    self_test_die "accepted a conformant gate that no workflow runs"

  echo "check-gates self-test passed: it rejects a missing, commented-out, uninvoked, silent, and CI-unrun self-test."
}

self_test

fail=0
checked=0
for script in scripts/*.sh; do
  [ "$(basename "$script")" = "$self" ] && continue
  checked=$((checked + 1))
  audit_gate "$script" ".github/workflows" || fail=1
done

# A verdict over nothing is not a pass: an empty scripts/ directory, or a glob
# that stopped matching, would otherwise report every gate as conformant.
if [ "$checked" -eq 0 ]; then
  echo "error: no gate scripts found in scripts/ — the enumeration is broken, not the tree." >&2
  exit 2
fi

if [ "$fail" -ne 0 ]; then
  echo "== gate conformance NOT met =="
  exit 1
fi
printf 'ok: %s gate script(s) self-test and are run by CI\n' "$checked"
