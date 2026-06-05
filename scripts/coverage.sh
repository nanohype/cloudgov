#!/usr/bin/env bash
#
# coverage.sh — run the test suite with coverage and enforce the floors.
#
# Produces coverage.out, prints total coverage, and fails if:
#   - any package falls below its floor in .coverage-floors;
#   - a floored package produces no coverage line (stale/typo'd name — its floor
#     would otherwise be silently unenforced);
#   - a package reports coverage but has no floor (new code must be gated).
# Floors ratchet: raise a package's floor when you raise its coverage. Run locally
# the same way CI does: scripts/coverage.sh
set -euo pipefail

cd "$(dirname "$0")/.."

profile="${1:-coverage.out}"
floors_file=".coverage-floors"
module="github.com/nanohype/cloudgov"

# One run produces both the merged profile and the per-package coverage lines.
out=$(go test ./... -coverprofile="$profile" -covermode=atomic -count=1)
echo "$out"

total=$(go tool cover -func="$profile" | awk '/^total:/ {gsub(/%/,"",$3); print $3}')
echo "== total coverage: ${total}% =="

fail=0
floored=" "
while read -r pkg floor; do
  case "$pkg" in '' | '#'*) continue ;; esac
  floored="${floored}${pkg} "
  line=$(printf '%s\n' "$out" | grep -E "[[:space:]]${module}/${pkg}[[:space:]]" || true)
  cov=$(printf '%s\n' "$line" | grep -oE "coverage: [0-9.]+%" | grep -oE "[0-9.]+" | head -1 || true)
  if [ -z "$cov" ]; then
    echo "::error::floored package ${pkg} produced no coverage line (stale name, or it has no test files?)"
    fail=1
    continue
  fi
  if awk "BEGIN{exit !($cov < $floor)}"; then
    echo "::error::${pkg} coverage ${cov}% is below its ${floor}% floor"
    fail=1
  else
    printf '  ok  %-26s %5s%% >= %s%%\n' "$pkg" "$cov" "$floor"
  fi
done < "$floors_file"

# Any package that reports coverage but isn't floored is ungated — fail so new
# tested code can't land without a floor.
covered=$(printf '%s\n' "$out" | awk -v m="${module}/" '/coverage: [0-9]/ {for (i=1;i<=NF;i++) if (index($i,m)==1) {sub(m,"",$i); print $i}}' | sort -u)
for pkg in $covered; do
  case "$floored" in
    *" $pkg "*) ;;
    *) echo "::error::package ${pkg} reports coverage but has no floor in ${floors_file}"; fail=1 ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  echo "== coverage floors NOT met =="
  exit 1
fi
echo "== all per-package coverage floors met =="
