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

profile="${1:-coverage.out}"
floors_file=".coverage-floors"
module="github.com/nanohype/cloudgov"

out=$(go test ./... -coverprofile="$profile" -covermode=atomic -count=1)
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
  local out="$1" file_cov="$2"
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
      echo "::error::${floors_file}: unknown floor kind '${kind}' (want 'package' or 'file')"
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
    else
      printf '  ok  %-52s %5s%% >= %s%%\n' "$label" "$cov" "$floor"
    fi
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
  if [ "$evaluated" -eq 0 ]; then
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

  echo "coverage self-test passed: the gate rejects below-floor, stale-path, unfloored and malformed entries."
}

self_test

if ! evaluate_floors "$out" "$file_cov" <"$floors_file"; then
  echo "== coverage floors NOT met =="
  exit 1
fi
echo "== all coverage floors met =="
