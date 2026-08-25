#!/usr/bin/env bash
# shellcheck disable=SC2016  # single-quoted $ here belongs to awk, not the shell
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

# shellcheck disable=SC1091  # resolved at run time from repo_root
. "${repo_root}/scripts/lib/tracked-files.sh"

self="$(basename "${BASH_SOURCE[0]}")"

# workflow_runs reports whether any workflow in $2 EXECUTES the script named $1.
#
# The question is about run: steps, and only about them. Searching the whole
# workflow answers a different question — it counts a step `name:`, an `env:`
# value, an `echo`, and a step carrying `if: false`, so a gate can be named all
# over a workflow and executed by none of it. Comments are stripped for the same
# reason one layer down: `# run: bash scripts/x.sh` documents an intention and
# runs nothing.
workflow_runs() {
  local name="$1" workflows="$2" file decommented
  for file in "$workflows"/*.yml "$workflows"/*.yaml; do
    [ -f "$file" ] || continue
    if ! decommented="$(awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$file")"; then
      echo "workflow_runs: the comment stripper failed on ${file}; it was not examined" >&2
      return 2
    fi
    # The extractor prefixes each line with its source line number so a caller
    # can cite it; that prefix is cut here, because the matcher below anchors on
    # command position and a citation would sit where the command belongs.
    if awk -f "${lib_dir}/workflow-run-steps.awk" <<<"$decommented" |
      cut -d: -f2- |
      grep -qE "$(invocation_pattern "$name")"; then
      return 0
    fi
  done
  return 1
}


# ── every job must be reachable from the merge gate ──────────────────────────
#
# Branch protection watches ONE check per workflow: the merge gate. A job the
# gate does not list in `needs:` still runs and still goes red, and at the point
# of decision that red job is indistinguishable from a green one — the merge is
# allowed either way. The failure is invisible in exactly the change that causes
# it, because adding a job looks complete without touching the gate.
#
# describe_workflow prints one record per line for $1:
#   JOB <id>    a top-level job
#   GATE <id>   the job that runs the merge-gate action
#   NEED <id>   an entry in the gate's needs list
describe_workflow() {
  local file="$1"
  awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$file" | awk '
    /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
    /^[a-zA-Z]/ { in_jobs = 0 }
    !in_jobs { next }

    # A job id under `jobs:`. Three things vary and all three were assumed:
    #
    #   the QUOTE   — YAML permits `deploy:`, '"'"'deploy'"'"': and "deploy":, and a
    #                 rule matching only the bare form makes a quoted job
    #                 invisible; it runs, it can go red, and it gates nothing.
    #   the INDENT  — two spaces is a convention, not a rule.
    #   the CHARSET — a quoted key may hold characters a bare one may not.
    #
    # The indent is taken from the FIRST job seen and every later key must match
    # it, so a nested map key at a deeper indent is not mistaken for a job.
    /^[[:space:]]+["'"'"']?[A-Za-z0-9_.-]+["'"'"']?:[[:space:]]*$/ {
      indent = match($0, /[^[:space:]]/)
      if (job_indent == 0) job_indent = indent
      if (indent == job_indent) {
        job = $0
        sub(/^[[:space:]]+/, "", job)
        sub(/:[[:space:]]*$/, "", job)
        gsub(/^["'"'"']|["'"'"']$/, "", job)
        print "JOB " job
        collecting = 0
        next
      }
    }

    # The gate job is the one whose steps run the merge-gate action. Identified
    # by what it DOES rather than by its name, so renaming it does not quietly
    # remove the check.
    /merge-gate@/ { print "GATE " job }

    # `needs:` at the JOB own level, not at any depth. The merge-gate action
    # takes an input literally called `needs`, nested two levels deeper inside
    # `with:`, and a depth-blind rule collects the expression there as if it were
    # a dependency list.
    /^[[:space:]]+needs:/ && match($0, /[^[:space:]]/) == job_indent + 2 {
      rest = $0
      sub(/^    needs:[[:space:]]*/, "", rest)
      gate_needs_job = job
      # A one-line `needs: [a, b]` is complete on its own line; a bracket left
      # open continues onto the lines below.
      collecting = (job != "" && rest !~ /\]/)
      emit(rest)
      next
    }
    # Any other key at job level ends the list. Without this the collector runs
    # to the end of the job and every token in it — `steps:`, an action ref, an
    # `if:` expression — is recorded as a dependency, so the gate reads as
    # covering jobs it has never heard of.
    collecting && /^[[:space:]]+["'"'"']?[A-Za-z0-9_.-]+["'"'"']?:/ { collecting = 0 }
    collecting { emit($0) }

    function emit(text,   n, i, parts, closed) {
      if (text ~ /^[[:space:]]*$/) return
      # Tested before the brackets are turned into separators, not after.
      closed = (text ~ /\]/)
      gsub(/[][,]/, " ", text)
      n = split(text, parts, /[[:space:]]+/)
      for (i = 1; i <= n; i++) {
        if (parts[i] == "" || parts[i] == "-") continue
        gsub(/^["'"'"']|["'"'"']$/, "", parts[i])
        print "NEED " gate_needs_job " " parts[i]
      }
      if (closed) collecting = 0
    }
  '
}

# NO EXEMPTIONS, because the enforcer that decides the merge has none.
#
# This rule mirrors the shared merge-gate action, which fails with "N job(s) in
# <workflow> are outside this gate" and offers no way to declare an exception. A
# local rule more permissive than the one that actually decides is worse than no
# local rule: it passes on a seat and fails in CI, which is exactly what it did.
#
# A job that legitimately must not block a merge — one whose verdict is a
# function of the world rather than of the tree — belongs in a workflow that
# carries no gate. That is a real place to put it, not an exemption.
check_merge_gate_coverage() {
  local workflows="$1" file base records gate needs job rc=0 gates_seen=0
  for file in "$workflows"/*.yml; do
    [ -f "$file" ] || continue
    base="$(basename "$file")"
    if ! records="$(describe_workflow "$file")"; then
      echo "::error::${base} could not be read; its jobs were not compared against any merge gate" >&2
      return 1
    fi
    gate="$(printf '%s\n' "$records" | awk '$1 == "GATE" { print $2; exit }')"
    # A workflow with no merge gate gates nothing by construction — a release
    # workflow on a tag, for instance. That is a different question from a gate
    # that misses a job, and conflating them would report every such workflow.
    [ -n "$gate" ] || continue
    gates_seen=$((gates_seen + 1))
    needs="$(printf '%s\n' "$records" | awk -v g="$gate" '$1 == "NEED" && $2 == g { print $3 }')"
    if [ -z "$needs" ]; then
      echo "::error::${base}: ${gate} runs the merge-gate action and lists no needs; it reports on nothing" >&2
      rc=1
      continue
    fi
    while IFS= read -r job; do
      [ -n "$job" ] || continue
      [ "$job" = "$gate" ] && continue
      printf '%s\n' "$needs" | grep -qx -- "$job" && continue
      echo "::error::${base}: job '${job}' is not in ${gate}'s needs; it runs, it can go red, and it does not block a merge. Move it to a workflow with no gate if it must not block one." >&2
      rc=1
    done < <(printf '%s\n' "$records" | awk '$1 == "JOB" { print $2 }')

  done
  if [ "$gates_seen" -eq 0 ]; then
    echo "error: no merge gate was found in any workflow — the detector is broken, or nothing gates a merge." >&2
    return 2
  fi
  printf 'ok: %s merge gate(s), every job in a gated workflow is one of its dependencies\n' "$gates_seen"
  return "$rc"
}

# ── Why this script self-tests ────────────────────────────────────────────────
#
# Its one check is a grep over YAML, which is the shape that silently matches
# nothing when a path convention changes — and reports that as every gate being
# wired.
# invocation_pattern builds the expression for "this line RUNS scripts/$1".
#
# COMMAND POSITION, not presence. The path appearing anywhere is satisfied by an
# `echo` that prints it, an `env:` value, a step name, and a sentence telling
# contributors not to run it — every position except the one that executes. Both
# halves of this gate ask the same question, so they share the answer: a
# divergence between them is a rule proven on one surface and assumed on the
# other.
#
# The interpreter is REQUIRED rather than optional, which excludes a bare
# `scripts/x.sh` invoked through its shebang. That form is legal and is read here
# as unwired — a visible false failure the author resolves by writing the
# interpreter, rather than a silent pass, which is the direction to be wrong in.
invocation_pattern() {
  printf '(^|`)[[:space:]]*(bash[[:space:]]+|sh[[:space:]]+|\./)scripts/%s([[:space:]]|`|$)' "$1"
}

# checklist_names reports whether $2 tells a contributor to RUN the gate $1.
#
# Named in command position, not merely mentioned. A sentence saying a gate was
# deleted and must not be run contains its path and satisfies a plain search,
# leaving the checklist missing the one line a contributor needs.
checklist_names() {
  local name="$1" doc="$2"
  grep -qE "$(invocation_pattern "$name")" "$doc"
}

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

  # Present in every position except the one that executes it.
  cat >"$tmp/workflows/mentioned.yml" <<'WF'
jobs:
  build:
    env:
      GATE: scripts/mentioned.sh
    steps:
      - name: skipped scripts/mentioned.sh
        if: false
        run: echo nothing
      - run: echo "see scripts/mentioned.sh for details"
WF
  ! workflow_runs "mentioned.sh" "$tmp/workflows" 2>/dev/null ||
    self_test_die "a gate named in a step name, an env value and a skipped step counted as CI running it"
  rm -f "$tmp/workflows/mentioned.yml"

  # The contributor-checklist half uses the same matcher, so one control covers
  # both: a name present is found, a name absent is not.
  # The PRODUCTION matcher, not a stand-in for it. A control exercising a
  # different expression than the one that ships proves nothing about the one
  # that ships.
  printf 'Run `bash scripts/wired.sh` before opening a PR.
' >"$tmp/CONTRIBUTING.md"
  checklist_names "wired.sh" "$tmp/CONTRIBUTING.md" ||
    self_test_die "a gate named in a checklist was not found in it"
  printf 'We used to run `scripts/removed.sh`; it is gone, do not run it.
' >>"$tmp/CONTRIBUTING.md"
  if checklist_names "removed.sh" "$tmp/CONTRIBUTING.md"; then
    self_test_die "a sentence telling contributors NOT to run a gate satisfied the checklist rule"
  fi
  if checklist_names "absent.sh" "$tmp/CONTRIBUTING.md"; then
    self_test_die "a gate the checklist does not name was found in it"
  fi

  # An empty workflow directory means nothing is wired, not that everything is.
  mkdir -p "$tmp/empty"
  ! workflow_runs "wired.sh" "$tmp/empty" 2>/dev/null ||
    self_test_die "reported a gate as wired against a directory with no workflows"

  # ── the merge-gate reachability check, both directions on one tree ──
  local wf
  wf="$tmp/wf/.github/workflows"
  mkdir -p "$wf"
  cat >"$wf/covered.yml" <<'YML'
name: covered
on: pull_request
jobs:
  alpha:
    runs-on: ubuntu-latest
    steps:
      - run: echo alpha
  merge-gate:
    runs-on: ubuntu-latest
    needs:
      [
        alpha,
      ]
    if: always()
    steps:
      - uses: nanohype/.github/actions/merge-gate@0000000000000000000000000000000000000000 # main
YML
  check_merge_gate_coverage "$wf" >/dev/null ||
    self_test_die "rejected a workflow whose gate lists every job"

  # ONE violation: the same tree gains a single ungated job.
  cat >"$wf/covered.yml" <<'YML'
name: covered
on: pull_request
jobs:
  alpha:
    runs-on: ubuntu-latest
    steps:
      - run: echo alpha
  beta:
    runs-on: ubuntu-latest
    steps:
      - run: echo beta
  merge-gate:
    runs-on: ubuntu-latest
    needs:
      [
        alpha,
      ]
    if: always()
    steps:
      - uses: nanohype/.github/actions/merge-gate@0000000000000000000000000000000000000000 # main
YML
  if check_merge_gate_coverage "$wf" >/dev/null 2>&1; then
    self_test_die "accepted a job the merge gate does not list; it would run, go red, and block no merge"
  fi
  # Captured before it is searched. Reading the status of `check | grep` gives
  # the pipeline's, which under pipefail is the checker's non-zero — so the
  # answer grep found is discarded and the assertion tests the wrong thing.
  local rejection
  rejection="$(check_merge_gate_coverage "$wf" 2>&1 >/dev/null || true)"
  printf '%s\n' "$rejection" | grep -qF "'beta'" ||
    self_test_die "rejected without naming the ungated job, so the rejection does not say what is wrong: ${rejection}"

  # A QUOTED job key, and one at a different indent. Both are legal YAML and
  # both were invisible: the rule matched a bare key at exactly two spaces, so a
  # job written either way ran, could go red, and gated nothing.
  cat >"$wf/quoted.yml" <<'YML'
name: quoted
on: pull_request
jobs:
    alpha:
      runs-on: ubuntu-latest
      steps:
        - run: echo alpha
    "deploy-to-prod":
      runs-on: ubuntu-latest
      steps:
        - run: echo deploying
    merge-gate:
      runs-on: ubuntu-latest
      needs:
        [
          alpha,
        ]
      if: always()
      steps:
        - uses: nanohype/.github/actions/merge-gate@0000000000000000000000000000000000000000 # main
YML
  if check_merge_gate_coverage "$wf" >/dev/null 2>&1; then
    self_test_die "a quoted job key at a four-space indent was invisible to the coverage check; it runs, it can go red, and it gates nothing"
  fi
  rejection="$(check_merge_gate_coverage "$wf" 2>&1 >/dev/null || true)"
  printf '%s\n' "$rejection" | grep -qF "deploy-to-prod" ||
    self_test_die "rejected without naming the quoted job: ${rejection}"
  rm -f "$wf/quoted.yml"

  # There is no exemption case to test, and its absence is the point: the shared
  # merge-gate action offers no way to declare one, so a local rule that did
  # would pass a branch CI rejects. The control above already proves it — an
  # ungated job is rejected with no way to excuse it.

  # A gate that depends on nothing reports on nothing.
  cat >"$wf/covered.yml" <<'YML'
name: covered
on: pull_request
jobs:
  alpha:
    runs-on: ubuntu-latest
    steps:
      - run: echo alpha
  merge-gate:
    runs-on: ubuntu-latest
    if: always()
    steps:
      - uses: nanohype/.github/actions/merge-gate@0000000000000000000000000000000000000000 # main
YML
  if check_merge_gate_coverage "$wf" >/dev/null 2>&1; then
    self_test_die "accepted a merge gate with no needs at all"
  fi

  # A workflow with no gate gates nothing by construction and is a different
  # question; reporting it would fire on every release workflow.
  rm -f "$wf/covered.yml"
  cat >"$wf/tagonly.yml" <<'YML'
name: tagonly
on:
  push:
    tags:
      - 'v*'
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: echo publish
YML
  # `cmd; [ $? -eq N ]` cannot be used here: under errexit the non-zero status
  # aborts before the test runs, so the branch that reads it is unreachable.
  local vacuous_rc=0
  check_merge_gate_coverage "$wf" >/dev/null 2>&1 || vacuous_rc=$?
  [ "$vacuous_rc" -eq 2 ] ||
    self_test_die "a directory whose workflows carry no merge gate must be an unanswerable question, not a pass (got ${vacuous_rc})"

  # ── the gate population is scripts/*.sh, not everything under scripts/ ──
  #
  # A shared library is a .sh file and is not a gate. The enumeration must stay
  # top-level: widened to recurse, it demanded that scripts/lib/tracked-files.sh
  # be run by a workflow and named in the contributor checklist.
  #
  # That widening PASSED on the seat and failed in CI, because the library was
  # untracked locally and committed there — the tracked set is the same in both
  # places only once everything is committed, and a file being added is exactly
  # when it is not.
  local population
  population="$(tracked_files . -name '*.sh' -type f | grep '^\./scripts/[^/]*\.sh$' | sed 's|^\./||' || true)"
  if printf '%s\n' "$population" | grep -q '^scripts/lib/'; then
    self_test_die "the gate population includes scripts/lib/; a shared library is not a gate and would be required to have a workflow step and a checklist line"
  fi
  printf '%s\n' "$population" | grep -q '^scripts/check-gates\.sh$' ||
    self_test_die "the gate population does not include this gate; the enumeration has stopped matching scripts/"

  echo "check-gates self-test passed: it rejects a commented-out run step, an unmentioned gate, an empty workflow directory, and a gate missing from the contributor checklist."
}

# The enumeration's precondition, named before anything depends on it. Without
# this the silent filesystem fallback restores the behaviour the tracked set
# replaced, and a small count is the only sign.
require_tracked_source "$repo_root" "check-gates" || exit 2

self_test

fail=0
checked=0
while IFS= read -r script; do
  name="$(basename "$script")"
  [ "$name" = "$self" ] && continue
  checked=$((checked + 1))
  if ! workflow_runs "$name" ".github/workflows"; then
    echo "::error::${name} is not run by any workflow; it guards nothing on a pull request" >&2
    fail=1
  fi
done < <(tracked_files . -name '*.sh' -type f | grep '^\./scripts/[^/]*\.sh$' | sed 's|^\./||' | sort)

# This script is a gate too, and a gate nothing runs is the case it exists for.
if ! workflow_runs "$self" ".github/workflows"; then
  echo "::error::${self} is not run by any workflow; the wiring check itself is unwired" >&2
  fail=1
fi

# ─── every CI job must be reachable from the merge gate ───
if ! check_merge_gate_coverage ".github/workflows"; then
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
while IFS= read -r script; do
  name="$(basename "$script")"
  if ! checklist_names "$name" CONTRIBUTING.md; then
    echo "::error::${name} is run by CI and is not named in CONTRIBUTING.md; a contributor following the checklist would fail on it" >&2
    fail=1
  fi
done < <(tracked_files . -name '*.sh' -type f | grep '^\./scripts/[^/]*\.sh$' | sed 's|^\./||' | sort)

# A verdict over nothing is not a pass: an empty scripts/ directory, or a glob
# that stopped matching, would otherwise report every gate as wired.
#
# A FLOOR WELL UNDER THE REAL COUNT, not at-least-one. "Matched almost nothing"
# is the failure that reads as success: an at-least-one floor is satisfied by the
# gate scripts themselves, or by one stray file, and reports a clean tree. This
# catches an enumeration that collapsed, and is set low enough that ordinary
# growth or deletion does not trip it.
readonly GATE_COUNT_FLOOR=5 # measured 7 gates besides this one
if [ "$checked" -lt "$GATE_COUNT_FLOOR" ]; then
  echo "error: found ${checked} gate script(s), under the floor of ${GATE_COUNT_FLOOR} — the enumeration collapsed." >&2
  exit 2
fi

if [ "$fail" -ne 0 ]; then
  echo "== gate wiring NOT met =="
  exit 1
fi
printf 'ok: %s gate script(s) run by CI and named in CONTRIBUTING.md (capability proven separately by check-positive-controls.sh)\n' "$checked"
