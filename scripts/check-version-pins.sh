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
lib_dir="${repo_root}/scripts/lib"
cd "$repo_root"

# ─── the classification ───
#
# Files that carry versions. Each must have every pin watched.
WATCHED_GLOBS=(".github/workflows/*.yml" "go.mod")

# Files asserted to carry no version at all. This is a claim about their content
# that this gate enforces, not a description of it.
NO_VERSION_FILES=(".goreleaser.yaml" "Taskfile.yml" ".golangci.yml" ".coverage-floors")

# ─── the rules, read from renovate.json rather than restated ───
#
# A gate carrying its own copy of the rule is a second source of truth. Deleting
# a customManager from renovate.json would leave this gate asserting coverage
# that no longer exists — reporting every pin as watched at the moment nothing
# watches them. So what a covered pin looks like is derived from the config, and
# a config with no usable customManager fails rather than passing everything.
renovate_annotation_pattern() {
  python3 "${lib_dir}/renovate-annotation.py" "$1"
}

# scan_unwatched prints one line per version-like pin in $1 that nothing watches.
#
# A pin is watched when it is either an action reference carrying a version
# comment (Renovate's built-in github-actions manager reads those) or annotated
# for a customManager in renovate.json. Anything else version-shaped is unwatched.
#
# The scan runs over two views of each line, and the split is the whole point.
# Comments are where the ANNOTATIONS live, so the raw line is read for coverage —
# but a version inside a comment is a mention rather than a pin, so the
# comment-stripped line is what is scanned for pins. Reading one view for both is
# how a gate accepts a pin whose trailing comment merely mentions renovate.
scan_unwatched() {
  local file="$1" annotation="$2"
  # The stripped view is read first and keyed by line number, so the two views of
  # a line are compared without inventing a field separator that could occur in
  # the source.
  awk -v annotation="$annotation" -v fname="$file" '
    NR == FNR { code[FNR] = $0; next }
    {
      raw  = $0
      line = code[FNR]

      # An action pinned to a sha with a version comment is read by the built-in
      # github-actions manager. That version lives in the comment, so this one is
      # matched against the raw line by design.
      if (raw ~ /uses:[[:space:]]*[^[:space:]]+@[0-9a-f]{40}[[:space:]]*#[[:space:]]*v?[0-9]/) { pending = 0; next }

      # A floating action tag is not a pin at all; the supply-chain gate rejects
      # it separately, so it is not this gate to report.
      if (raw ~ /uses:[[:space:]]*[^[:space:]]+@v?[0-9]+[[:space:]]*$/) { next }

      has_pin = (line ~ /[^0-9A-Za-z.]v?[0-9]+\.[0-9]+\.[0-9]+/)
      is_annotation = (raw ~ annotation)

      # An annotation covers exactly one pin. Sharing a line with its pin covers
      # that pin and nothing further; alone, it covers the next pin within a short
      # window. Covering a window rather than a pin would let one comment vouch
      # for every version beneath it.
      if (is_annotation) {
        if (has_pin) { pending = 0; next }
        pending = 1; window = 3; next
      }

      if (has_pin) {
        if (pending) { pending = 0; next }
        print fname ":" FNR ": " raw
        next
      }

      if (pending && --window <= 0) pending = 0
    }
  ' <(awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$file") "$file"
}

# scan_versions prints one line per version-like token in $1, watched or not,
# ignoring comments. Used for the files asserted to carry none: a version named
# in prose is a mention, and failing on one would push the next author to delete
# the sentence rather than the pin.
scan_versions() {
  local file="$1"
  awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$file" |
    grep -nE '(^|[^0-9A-Za-z.])v?[0-9]+\.[0-9]+\.[0-9]+' || true
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
  local tmp ann
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  ann="$ANNOTATION"

  # A sha-pinned action with a version comment is watched.
  printf '      - uses: actions/checkout@%040d # v7.0.1\n' 0 >"$tmp/watched-action.yml"
  [ -z "$(scan_unwatched "$tmp/watched-action.yml" "$ann")" ] ||
    self_test_die "reported a sha-pinned action with a version comment as unwatched"

  # A value pin behind a renovate annotation is watched.
  printf '          # renovate: datasource=github-releases depName=golangci/golangci-lint\n          version: v2.13.1\n' >"$tmp/watched-value.yml"
  [ -z "$(scan_unwatched "$tmp/watched-value.yml" "$ann")" ] ||
    self_test_die "reported an annotated value pin as unwatched"

  # The same pin without the annotation is not.
  printf '          version: v2.13.1\n' >"$tmp/unwatched.yml"
  [ -n "$(scan_unwatched "$tmp/unwatched.yml" "$ann")" ] ||
    self_test_die "accepted a value pin that nothing watches"

  printf '        run: |\n          go install golang.org/x/vuln/cmd/govulncheck@v1.1.4\n' >"$tmp/unwatched-install.yml"
  [ -n "$(scan_unwatched "$tmp/unwatched-install.yml" "$ann")" ] ||
    self_test_die "accepted an unannotated go install pin"

  # An annotation covers one pin, not the file beneath it.
  printf '          # renovate: datasource=pypi depName=zizmor\n          pipx install zizmor==1.16.3\n          version: v9.9.9\n          version: v8.8.8\n' >"$tmp/annotation-scope.yml"
  [ -n "$(scan_unwatched "$tmp/annotation-scope.yml" "$ann")" ] ||
    self_test_die "a renovate annotation was treated as covering the rest of the file"

  # An annotation sharing a line with its pin covers that pin and stops there.
  # Before comments and code were read as separate views, the whole line was
  # skipped: the pin was neither reported nor genuinely covered, and the next pin
  # inherited the annotation.
  printf '          version: v1.2.3 # renovate: datasource=go depName=example/one\n          version: v4.5.6\n' >"$tmp/inline-annotation.yml"
  out="$(scan_unwatched "$tmp/inline-annotation.yml" "$ann")"
  case "$out" in
    *v4.5.6*) ;;
    *) self_test_die "an inline annotation covered the pin on the following line as well" ;;
  esac
  case "$out" in
    *v1.2.3*) self_test_die "an inline annotation did not cover the pin on its own line" ;;
  esac

  # A version appearing only inside a comment is a mention, not a pin.
  printf '          # bumped past v9.9.9 in the changelog\n          image: alpine\n' >"$tmp/mention.yml"
  [ -z "$(scan_unwatched "$tmp/mention.yml" "$ann")" ] ||
    self_test_die "a version mentioned in a comment was reported as an unwatched pin"

  # The no-version assertion detects a version appearing in an exempted file.
  printf 'tasks:\n  build:\n    cmds:\n      - go build ./...\n' >"$tmp/clean.yml"
  [ -z "$(scan_versions "$tmp/clean.yml")" ] ||
    self_test_die "found a version in a file that carries none"

  printf 'image: alpine:3.21.0\n' >"$tmp/dirty.yml"
  [ -n "$(scan_versions "$tmp/dirty.yml")" ] ||
    self_test_die "a version appearing in a no-version file went undetected"

  # The rules come from renovate.json. A config that cannot support the gate is an
  # error, never an empty pattern that would match nothing.
  printf '{"customManagers": []}\n' >"$tmp/empty-renovate.json"
  ! renovate_annotation_pattern "$tmp/empty-renovate.json" >/dev/null 2>&1 ||
    self_test_die "derived an annotation pattern from a config declaring no customManagers"

  printf '{"customManagers": [{"matchStrings": ["version: (?<currentValue>.*)"]}]}\n' >"$tmp/opaque-renovate.json"
  ! renovate_annotation_pattern "$tmp/opaque-renovate.json" >/dev/null 2>&1 ||
    self_test_die "accepted a customManager whose coverage this gate cannot determine"

  echo "check-version-pins self-test passed: it rejects unwatched pins, annotation over-reach, comment-only mentions, a version in an exempt file, and a renovate.json it cannot read."
}

# The pattern is derived before the self-test so a config the gate cannot read
# stops the run rather than being reported as a clean tree.
ANNOTATION="$(renovate_annotation_pattern renovate.json)"

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
    unwatched=$(scan_unwatched "$file" "$ANNOTATION")
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

# ─── the rule must match something ───
#
# A customManager that matches nothing in the tree is dead: it is a rule that has
# stopped applying, and it reports the same as a rule that applies everywhere.
# Same failure shape as an empty enumeration, one level up. So the annotation the
# config keys on has to appear in the tree, or the config is stale.
annotated_pins=0
for glob in "${WATCHED_GLOBS[@]}"; do
  for file in $glob; do
    [ -f "$file" ] || continue
    if grep -qE "$ANNOTATION" "$file"; then
      annotated_pins=$((annotated_pins + 1))
    fi
  done
done
if [ "$annotated_pins" -eq 0 ]; then
  echo "::error::renovate.json declares a customManager keyed on a '# renovate:' annotation, and no file in the watched set carries one. The rule matches nothing, so it protects nothing." >&2
  fail=1
fi

# ─── the exemptions must be asserted, not described ───
#
# The no-version classification is already an assertion: a listed file that
# acquires a version fails above. The other half is the one that rots toward
# permissive — a listed file that has nothing to say. If a file never had a
# version and never could, listing it here is a description of the world rather
# than a constraint on it, and it dilutes the list until nobody reads it.
#
# So every entry must be a file that the pin scanner would actually have an
# opinion about: one this repo writes and CI reads. A path that no longer exists
# already fails above.
for file in "${NO_VERSION_FILES[@]}"; do
  [ -f "$file" ] || continue
  if [ ! -s "$file" ]; then
    echo "::error::${file} is classified as carrying no version but is empty; the entry asserts nothing" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "== version-pin coverage NOT met =="
  exit 1
fi
printf 'ok: %s file(s) with every pin watched; %s file(s) asserted to carry no version\n' \
  "$watched_files" "${#NO_VERSION_FILES[@]}"
