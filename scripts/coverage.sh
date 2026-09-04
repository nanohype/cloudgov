#!/usr/bin/env bash
#
# coverage.sh — run the test suite with coverage and enforce the floors.
#
# Two kinds of floor, both declared in .coverage-floors:
#
#   package <pkg> <pct>   the statement floor for a package
#   file    <path> <pct>  the statement floor for one file
#
# The per-file kind exists for the security-critical path — secret handling and
# the merge-gate exit code this tool's own output is consumed through. A package
# floor averages those files with everything around them, so a package can sit
# comfortably above its floor while an uncovered branch in the secret scanner
# ships. Those files are pinned at 100 and the gate reads them individually.
#
# Fails if:
#   - a package or file falls below its floor;
#   - a floored package or file produces no coverage data (stale/typo'd path — its
#     floor would otherwise be silently unenforced);
#   - a package reports coverage but has no floor (new code must be gated).
#
# Floors ratchet: raise a package's floor when you raise its coverage.
#
# Run locally the same way CI does: scripts/coverage.sh
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root="$(pwd)"

# shellcheck disable=SC1091  # resolved at run time
. "${repo_root}/scripts/lib/tracked-files.sh"

require_tools grep awk go || exit 2

# The org floor and where it comes from, named once for the gate and its
# messages — and for those only. .coverage-floors and CONTRIBUTING.md each state
# 75 in prose, deriving it from nothing, so three places can disagree and a
# change here leaves two of them asserting the old value. The self-test below is
# what holds this one; the other two are held by reading.
#
# The standard publishes four floors — branches 60, lines 75, functions 75,
# statements 75. `go test -cover` reports statements and nothing else, so this is
# the one of the four a Go toolchain can assert. The other three are recorded as
# unasserted in CONTRIBUTING.md rather than left to look enforced.
readonly ORG_COVERAGE_FLOOR=75
readonly STANDARD_SOURCE="nanohype/standards/testing-rubric.json"

profile="${1:-coverage.out}"
floors_file=".coverage-floors"
module="github.com/nanohype/cloudgov"

# Captured to be parsed, and printed either way. Under `set -e` a failing `go
# test` aborted here with the output still inside $out, so the gate exited 1
# having printed NOTHING on either stream — the reader is told the coverage gate
# failed and not which test did.
if ! out=$(go test ./... -coverprofile="$profile" -covermode=atomic -count=1 2>&1); then
  printf '%s\n' "$out"
  echo "== coverage NOT met ==" >&2
  echo "error: the test run failed, so there is no coverage to measure." >&2
  exit 1
fi
echo "$out"

total=$(go tool cover -func="$profile" | awk '/^total:/ {gsub(/%/,"",$3); print $3}')
echo "== total coverage: ${total}% =="

# Per-file statement coverage, aggregated from the per-function report: sum the
# statements each function contributes and the ones it covers, keyed by file.
# `go tool cover -func` prints "<file>:<line>:\t<func>\t<pct>%", which has no
# statement counts, so the profile itself is the source — mode line dropped, then
# "<file>:<range> <numstmt> <count>" summed per file.
#
# A block whose source carries //coverage:ignore counts as covered. It is the
# escape hatch for a branch that cannot be reached, where the alternative is
# either a permanently red gate or deleting a defensive error check. Every marker
# states why, and the gate reports how many were honoured so they cannot pile up
# unnoticed.
file_cov=$(awk -v m="${module}/" -v root="$PWD" '
  NR > 1 {
    split($1, a, ":"); f = a[1]
    sub(m, "", f)
    split($1, r, ":"); split(r[2], se, ",")
    split(se[1], s1, "."); split(se[2], s2, ".")
    start[NR] = s1[1]; end[NR] = s2[1]; file[NR] = f; stmts[NR] = $2; cnt[NR] = $3
    files[f] = 1
  }
  END {
    # Slurp each file once and record which lines carry the ignore marker.
    for (f in files) {
      n = 0
      while ((getline line < (root "/" f)) > 0) {
        n++
        if (index(line, "//coverage:ignore") > 0) mark[f, n] = 1
      }
      close(root "/" f)
    }
    for (i in file) {
      f = file[i]
      total[f] += stmts[i]
      ok = (cnt[i] > 0)
      if (!ok) {
        for (l = start[i]; l <= end[i]; l++) if (mark[f, l]) { ok = 1; ignores[f] += stmts[i]; break }
      }
      if (ok) covered[f] += stmts[i]
    }
    for (f in total) printf "%s %.1f %d\n", f, (covered[f] * 100.0) / total[f], ignores[f] + 0
  }
' "$profile")

# evaluate_floors compares declared floors against measured coverage, printing one
# line per floor. Floors arrive on stdin and both measurements as arguments, so
# the self-test can drive it with synthetic data rather than needing a tree that
# is genuinely below its floor.
#
# Returns 1 when any floor is unmet, a floored target produced no data, or a
# covered package carries no floor.
evaluate_floors() {
  local out="$1" file_cov="$2" total="${3:-}"
  local fail=0
  local floored_pkgs=" "
  local evaluated=0
  local line kind target floor cov ign label pkg covered

  while read -r line; do
    # Strip trailing comments so a floor may carry its justification inline.
    line="${line%%#*}"
    read -r kind target floor extra <<<"$line"
    [ -n "${kind:-}" ] || continue

    # ─── the floor VALUE, before anything is compared against it ───
    #
    # This gate READS .coverage-floors and interpolates the floor straight into
    # an awk expression. An unvalidated value is not a typo that fails loudly:
    # a non-numeric floor becomes an uninitialised awk variable worth 0, so the
    # comparison is false and the entry prints a green `ok` line — while still
    # incrementing the evaluated denominator, so the anti-vacuity check reads as
    # satisfied too. A missing third field makes the awk a syntax error, whose
    # non-zero exit is likewise read as "not below floor".
    #
    # Silent on both sides is exactly the shape this file's own kind check was
    # written to catch, one field to the left.
    case "$floor" in
      "" )
        echo "::error::${floors_file}: '${kind} ${target}' declares no floor; a floor line with no number enforces nothing"
        fail=1
        continue
        ;;
      *[!0-9.]* | *.*.* | . )
        echo "::error::${floors_file}: '${kind} ${target}' declares floor '${floor}', which is not a number; it would compare as zero and pass anything"
        fail=1
        continue
        ;;
    esac
    if [ -n "${extra:-}" ]; then
      echo "::error::${floors_file}: '${kind} ${target} ${floor}' carries trailing content '${extra}'; a floor line is three fields and the rest is silently discarded"
      fail=1
      continue
    fi

    case "$kind" in
    total)
      # The whole-tree number, which no per-package floor can constrain: every
      # package can sit above its own floor while the total sits under the org
      # floor, because each package floor was set from its own measurement.
      cov="$total"
      label="total   coverage"
      ;;
    package)
      floored_pkgs="${floored_pkgs}${target} "
      line=$(printf '%s\n' "$out" | grep -E "[[:space:]]${module}/${target}[[:space:]]" || true)
      cov=$(printf '%s\n' "$line" | grep -oE "coverage: [0-9.]+%" | grep -oE "[0-9.]+" | head -1 || true)
      label="package ${target}"
      ;;
    file)
      cov=$(printf '%s\n' "$file_cov" | awk -v f="$target" '$1 == f {print $2}')
      ign=$(printf '%s\n' "$file_cov" | awk -v f="$target" '$1 == f {print $3}')
      label="file    ${target}"
      [ "${ign:-0}" -gt 0 ] 2>/dev/null && label="${label} (${ign} stmt ignored)"
      ;;
    *)
      echo "::error::${floors_file}: unknown floor kind '${kind}' (want 'total', 'package' or 'file')"
      fail=1
      continue
      ;;
    esac

    if [ -z "$cov" ]; then
      echo "::error::floored ${kind} ${target} produced no coverage data (stale path, or no test files?)"
      fail=1
      continue
    fi
    evaluated=$((evaluated + 1))
    if awk "BEGIN{exit !($cov < $floor)}"; then
      echo "::error::${label} coverage ${cov}% is below its ${floor}% floor"
      fail=1
      continue
    fi

    # The org floor, asserted where it can be.
    #
    # A per-package floor is a ratchet set from that package's own measurement,
    # so every package can sit above its own number while the tree sits under the
    # org standard's. Naming the standard in a comment and gating on the ratchet
    # is what let a package cross 75 and drift back under it with a green run.
    #
    # So: a package that MEASURES at or above the org floor must CARRY a floor at
    # or above it. Non-circular, and it needs no list — the population is every
    # package that has met the standard, read from the measurement rather than
    # remembered. Once a package meets the bar it cannot quietly stop meeting it,
    # and the tree ratchets toward the standard one package at a time instead of
    # waiting on a single number nobody can move alone.
    #
    # A package still under the org floor is held to its own ratchet and named in
    # the debt section, which is what ${floors_file} is for.
    if [ "$kind" = "package" ] &&
      awk "BEGIN{exit !($cov >= $ORG_COVERAGE_FLOOR)}" &&
      awk "BEGIN{exit !($floor < $ORG_COVERAGE_FLOOR)}"; then
      echo "::error::${label} measures ${cov}%, at or above the org floor of ${ORG_COVERAGE_FLOOR}% (${STANDARD_SOURCE}), but carries a floor of ${floor}%. Raise it to ${ORG_COVERAGE_FLOOR} or above: a package that has met the standard must not be free to fall back under it."
      fail=1
      continue
    fi

    printf '  ok  %-52s %5s%% >= %s%%\n' "$label" "$cov" "$floor"
  done

  # Any package that reports coverage but isn't floored is ungated — fail so new
  # tested code can't land without a floor.
  covered=$(printf '%s\n' "$out" | awk -v m="${module}/" '/coverage: [0-9]/ {for (i=1;i<=NF;i++) if (index($i,m)==1) {sub(m,"",$i); print $i}}' | sort -u)
  for pkg in $covered; do
    case "$floored_pkgs" in
    *" $pkg "*) ;;
    *)
      echo "::error::package ${pkg} reports coverage but has no floor in ${floors_file}"
      fail=1
      ;;
    esac
  done

  # The denominator. A floors file that stopped being read, or a glob that stopped
  # matching, produces the same silence as a tree that meets every floor.
  # The default is the FAILING value, and that direction is the fix. An empty
  # operand to a numeric test exits 2 with "integer expected", and in an `if` a 2
  # reads as false — so the floor is not evaluated to false, it is SKIPPED, and the
  # skip looks exactly like a pass. Defaulting to 0 would be the defect written
  # into its own fix: 0 is a clean count and is what an absent tool most resembles.
  if [ "${evaluated:-0}" -eq 0 ]; then
    echo "::error::no floors were evaluated — ${floors_file} was not read, which is not the same as every floor being met" >&2
    return 1
  fi
  printf '  --  %s floor(s) evaluated\n' "$evaluated"

  return "$fail"
}

# ── Why this script self-tests ────────────────────────────────────────────────
#
# This gate is cited as evidence that a package's coverage has not regressed, so
# a reader who sees it pass stops looking. A check that cannot fail reports
# success just as loudly as one that can, and the shapes it is supposed to catch
# — a below-floor package, a floor naming a path that no longer exists, a new
# package with no floor at all — are exactly the shapes that produce no other
# signal.
#
# So it proves it can reject before it is allowed to report a pass: each rejection
# is driven against synthetic measurements, and a clean set is required to come
# back silent so the gate is not simply always-red.
self_test_die() {
  echo "coverage self-test FAILED: $*" >&2
  echo "The gate could not be shown to reject, so its pass is not evidence." >&2
  exit 1
}

self_test() {
  local clean_out clean_files
  clean_out='ok  	'"${module}"'/internal/alpha	0.1s	coverage: 90.0% of statements'
  clean_files='internal/alpha/a.go 100.0 0'

  # A floor that is met, and a file floor that is met, must pass.
  if ! evaluate_floors "$clean_out" "$clean_files" >/dev/null <<-'EOF'
	package internal/alpha  85
	file    internal/alpha/a.go  100
	EOF
  then
    self_test_die "rejected a tree that meets every floor"
  fi

  # Below its floor.
  if evaluate_floors "$clean_out" "$clean_files" >/dev/null <<-'EOF'
	package internal/alpha  95
	EOF
  then
    self_test_die "accepted a package below its floor"
  fi

  # A package that has met the org floor and carries a floor below it. Without
  # this the standard is named in prose and gated by nothing, which is the state
  # that let a package cross 75 and be free to drift back under with a green run.
  if evaluate_floors "$clean_out" "$clean_files" >/dev/null <<-'EOF'
	package internal/alpha  70
	EOF
  then
    self_test_die "accepted a package measuring above the org floor whose floor sits below it"
  fi

  # And the other half, because a rule that rejects everything is not a rule: a
  # package still under the org floor is held to its own ratchet, not to 75.
  # Without this case the check above is satisfiable by refusing every floor
  # under 75, which would make the debt section unlandable.
  if ! evaluate_floors \
    'ok  	'"${module}"'/internal/beta	0.1s	coverage: 60.0% of statements' \
    'internal/beta/b.go 60.0 0' >/dev/null <<-'EOF'
	package internal/beta  55
	EOF
  then
    self_test_die "rejected a package below the org floor that meets its own ratchet"
  fi

  # THE BOUND ITSELF, from each side.
  #
  # The two cases above hold the RULE and not the NUMBER: with
  # ORG_COVERAGE_FLOOR lowered to 74, 73, 72 or 71 every one of them still
  # passes, because 90 is above all of those and 60 is below all of them. A gate
  # whose whole product is the assertion of one number needs a case on each side
  # of that number, which is the rule this repository's own contributing guide
  # states for a bound.
  #
  # Just under: a package measuring 74.9 has NOT met the standard and is held to
  # its own ratchet. Lowering the constant by one makes this case fail.
  if ! evaluate_floors \
    'ok  	'"${module}"'/internal/justunder	0.1s	coverage: 74.9% of statements' \
    'internal/justunder/c.go 74.9 0' >/dev/null <<-'EOF'
	package internal/justunder  70
	EOF
  then
    self_test_die "held a package measuring just under the org floor to the org floor; the constant has moved down"
  fi

  # Exactly at it: "measures AT or above" is the word the comparison implements,
  # so a package measuring exactly the org floor must be required to carry it.
  # Relaxing >= to > makes this case pass silently.
  if evaluate_floors \
    'ok  	'"${module}"'/internal/exactly	0.1s	coverage: 75.0% of statements' \
    'internal/exactly/d.go 75.0 0' >/dev/null <<-'EOF'
	package internal/exactly  70
	EOF
  then
    self_test_die "accepted a package measuring exactly the org floor with a floor below it; either the constant has moved up or the comparison is > rather than >="
  fi

  # The org-floor rule is confined to package floors, and this case is what
  # confines it. A total and a file floor are different claims from a package's:
  # the total is the number no package floor can constrain, and a file floor is
  # pinned at what that one file must hold rather than ratcheted toward a package
  # standard. Both stay at their own number even when what they measure sits at
  # or above the org floor. Drop the kind guard and this case is refused.
  if ! evaluate_floors "$clean_out" "$clean_files" 80 >/dev/null <<-'EOF'
	total   coverage             60
	package internal/alpha       85
	file    internal/alpha/a.go  60
	EOF
  then
    self_test_die "held a total or a file floor to the org floor; that rule is for package floors"
  fi

  # A floor naming a package with no coverage data — a stale or typo'd path,
  # whose floor would otherwise be silently unenforced.
  if evaluate_floors "$clean_out" "$clean_files" >/dev/null <<-'EOF'
	package internal/alpha  85
	package internal/renamed  85
	EOF
  then
    self_test_die "accepted a floor naming a package that produced no coverage"
  fi

  # A file floor naming a path the profile does not carry.
  if evaluate_floors "$clean_out" "$clean_files" >/dev/null <<-'EOF'
	package internal/alpha  85
	file    internal/alpha/gone.go  100
	EOF
  then
    self_test_die "accepted a file floor naming a path with no coverage data"
  fi

  # A covered package with no floor: new code landing ungated.
  if evaluate_floors "${clean_out}"$'\n''ok  	'"${module}"'/internal/beta	0.1s	coverage: 90.0% of statements' \
    "$clean_files" >/dev/null <<-'EOF'
	package internal/alpha  85
	EOF
  then
    self_test_die "accepted a covered package carrying no floor"
  fi

  # A file floor below its measured coverage.
  if evaluate_floors "$clean_out" 'internal/alpha/a.go 40.0 0' >/dev/null <<-'EOF'
	package internal/alpha  85
	file    internal/alpha/a.go  100
	EOF
  then
    self_test_die "accepted a file below its floor"
  fi

  # A floors file that yields no entries is not a tree that meets every floor.
  if evaluate_floors "$clean_out" "$clean_files" >/dev/null 2>&1 </dev/null; then
    self_test_die "reported a pass having evaluated no floors at all"
  fi

  # An unknown floor kind is a malformed declaration, not an entry to skip.
  if evaluate_floors "$clean_out" "$clean_files" >/dev/null <<-'EOF'
	package internal/alpha  85
	module  internal/alpha  85
	EOF
  then
    self_test_die "accepted an unknown floor kind"
  fi

  # ── the total floor, both directions ──
  #
  # The whole-tree number is the one no per-package floor can constrain: each
  # package floor was set from its own measurement, so all of them can be met
  # while the total sits under the org floor.
  if ! evaluate_floors "$clean_out" "$clean_files" 80 >/dev/null <<-'EOF'
	total    coverage             75
	package  internal/alpha       85
	file     internal/alpha/a.go  100
	EOF
  then
    self_test_die "rejected a tree whose total meets its floor"
  fi
  # Every package still meets its own floor; only the total is short. This is the
  # case a per-package floor set cannot see, and it is why the entry exists.
  if evaluate_floors "$clean_out" "$clean_files" 70 >/dev/null <<-'EOF'
	total    coverage             75
	package  internal/alpha       85
	file     internal/alpha/a.go  100
	EOF
  then
    self_test_die "accepted a total below its floor while every package met its own"
  fi

  echo "coverage self-test passed: the gate rejects below-floor, stale-path, unfloored and malformed entries, and a package that has met the org floor whose floor sits below it — while still accepting one under the org floor that meets its own ratchet. The org floor itself is pinned from both sides: 74.9 is held to its own ratchet and 75.0 is not. That rule reaches package floors only; a total and a file floor stay at their own number."
}

self_test

if ! evaluate_floors "$out" "$file_cov" "$total" <"$floors_file"; then
  echo "== coverage floors NOT met =="
  exit 1
fi
echo "== all coverage floors met =="
