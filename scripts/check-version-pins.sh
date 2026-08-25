#!/usr/bin/env bash
#
# check-version-pins.sh — assert that every version pinned in the tree is watched
# by something that can bump it, and that every file exempted from that is
# asserted to carry no version rather than described as carrying none.
#
# Two halves, both required.
#
# The first: an unwatched pin goes stale silently. The step it configures keeps
# reporting green — a lint version, a scanner version and a releaser version all
# produce a verdict whether or not they are current, so nothing surfaces the drift
# until the pinned release is old enough to be missing a check that matters.
#
# The second is the documentation rule made executable. A comment saying "this
# file carries no version" is true when written and nothing keeps it true; the
# first pin added below it makes the comment a confident false statement with no
# tell. So the classification is an assertion instead: a file listed as carrying
# no version fails this gate the moment one appears in it.
#
# What watches what:
#   - actions pinned as `uses: owner/repo@<sha> # vX.Y.Z` — Renovate's built-in
#     github-actions manager, which reads the version from the trailing comment.
#   - a version pinned as a VALUE (a tool version passed to an action, a
#     `go install ...@vX` argument, a `pipx install pkg==X`) — no standard manager
#     reads these, so each carries a `# renovate: datasource=... depName=...`
#     comment and the customManager in renovate.json matches on it.
#   - go.mod / go.sum — Renovate's gomod manager.
#
# Usage: scripts/check-version-pins.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

# ─── the classification ───
#
# Files that carry versions. Each must have every pin watched.
WATCHED_GLOBS=(".github/workflows/*.yml" "go.mod")

# Files asserted to carry no version at all. This is a claim about their content
# that this gate enforces, not a description of it.
NO_VERSION_FILES=(".goreleaser.yaml" "Taskfile.yml" ".golangci.yml" ".coverage-floors")

# scan_unwatched prints one line per version-like pin in $1 that nothing watches.
#
# A pin is watched when it is either an action reference carrying a version
# comment, or preceded by a `renovate:` annotation naming its datasource. Anything
# else version-shaped is unwatched.
scan_unwatched() {
  local file="$1"
  awk '
    # A renovate annotation covers ONE pin: the next version-carrying line within a
    # short window. Letting it cover a window rather than a line would make a
    # single annotation launder every pin beneath it.
    /#[[:space:]]*renovate:[[:space:]]*datasource=/ { pending = 1; window = 3; next }
    {
      if (pending) {
        if ($0 ~ /[0-9]+\.[0-9]+/) { pending = 0; next }
        if (--window <= 0) pending = 0
      }
    }
    # An action pinned to a sha with a version comment is read by the built-in
    # github-actions manager.
    /uses:[[:space:]]*[^[:space:]]+@[0-9a-f]{40}[[:space:]]*#[[:space:]]*v?[0-9]/ { next }
    # A floating action tag is not a pin at all; the supply-chain gate rejects it
    # separately, so it is not this gate to report.
    /uses:[[:space:]]*[^[:space:]]+@v?[0-9]+[[:space:]]*$/ { next }
    # Comments carry prose, not pins.
    /^[[:space:]]*#/ { next }
    # What is left and looks like a version is unwatched.
    /[^0-9A-Za-z.]v?[0-9]+\.[0-9]+\.[0-9]+/ { print FILENAME ":" FNR ": " $0 }
  ' "$file"
}

# scan_versions prints one line per version-like token in $1, watched or not. Used
# for the files asserted to carry none.
scan_versions() {
  local file="$1"
  grep -nE '(^|[^0-9A-Za-z.])v?[0-9]+\.[0-9]+\.[0-9]+' "$file" || true
}

# ── Why this script self-tests ────────────────────────────────────────────────
#
# It reports on the currency of everything else, so a false pass here withdraws
# the guarantee from every pin at once while printing green. Both scans are
# grep-shaped, which is the shape that silently matches nothing when a pattern
# stops fitting the file it reads.
self_test_die() {
  echo "check-version-pins self-test FAILED: $*" >&2
  echo "The gate could not be shown to reject, so its pass is not evidence." >&2
  exit 1
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # A sha-pinned action with a version comment is watched.
  printf '      - uses: actions/checkout@%040d # v7.0.1\n' 0 >"$tmp/watched-action.yml"
  [ -z "$(scan_unwatched "$tmp/watched-action.yml")" ] ||
    self_test_die "reported a sha-pinned action with a version comment as unwatched"

  # A value pin behind a renovate annotation is watched.
  cat >"$tmp/watched-value.yml" <<'WV'
          # renovate: datasource=github-releases depName=golangci/golangci-lint
          version: v2.13.1
WV
  [ -z "$(scan_unwatched "$tmp/watched-value.yml")" ] ||
    self_test_die "reported an annotated value pin as unwatched"

  # The same pin without the annotation is not.
  printf '          version: v2.13.1\n' >"$tmp/unwatched.yml"
  [ -n "$(scan_unwatched "$tmp/unwatched.yml")" ] ||
    self_test_die "accepted a value pin that nothing watches"

  cat >"$tmp/unwatched-install.yml" <<'UI'
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
UI
  [ -n "$(scan_unwatched "$tmp/unwatched-install.yml")" ] ||
    self_test_die "accepted an unannotated go install pin"

  # An annotation covers the pin it precedes, not the whole file.
  cat >"$tmp/annotation-scope.yml" <<'AS'
          # renovate: datasource=pypi depName=zizmor
          pipx install zizmor==1.16.3
          version: v9.9.9
          version: v8.8.8
AS
  [ -n "$(scan_unwatched "$tmp/annotation-scope.yml")" ] ||
    self_test_die "a renovate annotation was treated as covering the rest of the file"

  # The no-version assertion detects a version appearing in an exempted file.
  printf 'tasks:\n  build:\n    cmds:\n      - go build ./...\n' >"$tmp/clean.yml"
  [ -z "$(scan_versions "$tmp/clean.yml")" ] ||
    self_test_die "found a version in a file that carries none"

  printf 'image: alpine:3.21.0\n' >"$tmp/dirty.yml"
  [ -n "$(scan_versions "$tmp/dirty.yml")" ] ||
    self_test_die "a version appearing in a no-version file went undetected"

  echo "check-version-pins self-test passed: it rejects unwatched pins, annotation over-reach, and a version in an exempt file."
}

self_test

fail=0
watched_files=0

for glob in "${WATCHED_GLOBS[@]}"; do
  for file in $glob; do
    [ -f "$file" ] || continue
    watched_files=$((watched_files + 1))
    # go.mod is read wholesale by Renovate's gomod manager, so every version in
    # it is watched by construction.
    [ "$file" = "go.mod" ] && continue
    unwatched=$(scan_unwatched "$file")
    if [ -n "$unwatched" ]; then
      echo "::error::${file}: version pin(s) nothing can bump — add a '# renovate: datasource=... depName=...' comment above each:" >&2
      printf '%s\n' "$unwatched" >&2
      fail=1
    fi
  done
done

# A verdict over nothing is not a pass: a glob that stopped matching would
# otherwise report every pin as watched.
if [ "$watched_files" -eq 0 ]; then
  echo "error: the watched globs matched no files — the enumeration is broken, not the tree." >&2
  exit 2
fi

for file in "${NO_VERSION_FILES[@]}"; do
  if [ ! -f "$file" ]; then
    echo "::error::${file} is classified as carrying no version but does not exist; the classification names a file that is gone" >&2
    fail=1
    continue
  fi
  found=$(scan_versions "$file")
  if [ -n "$found" ]; then
    echo "::error::${file} is classified as carrying no version, and now carries one. Either move it to the watched set with a renovate annotation, or remove the version:" >&2
    printf '%s\n' "$found" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "== version-pin coverage NOT met =="
  exit 1
fi
printf 'ok: %s file(s) with every pin watched; %s file(s) asserted to carry no version\n' \
  "$watched_files" "${#NO_VERSION_FILES[@]}"
