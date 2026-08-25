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
WATCHED_GLOBS=(".github/workflows/*.yml" ".github/workflows/*.yaml" "go.mod")

# Files asserted to carry no version at all. This is a claim about their content
# that this gate enforces, not a description of it.
NO_VERSION_FILES=(".goreleaser.yaml" "Taskfile.yml" ".golangci.yml" ".coverage-floors")

# ─── the rules, applied from renovate.json rather than restated ───
#
# A gate carrying its own copy of the rule is a second source of truth. Deleting
# or breaking a customManager would leave this gate asserting coverage that no
# longer exists — reporting every pin as watched at the moment nothing watches
# them.
#
# renovate-annotation.py does not describe the rule, it RUNS it: each configured
# matchString is compiled and applied to the watched files, and the line carrying
# each matched `currentValue` comes back as covered. A manager matching nothing is
# an error rather than an empty answer, because "no coverage" and "total
# coverage" are the same silence otherwise.
#
# It reads the files raw. Renovate reads whole files, and these annotations LIVE
# in comments — asking "would Renovate match here" against a stripped view would
# declare a live manager dead.
renovate_covered_lines() {
  python3 "${lib_dir}/renovate-annotation.py" "$1" "${@:2}"
}

# scan_unwatched prints one line per version-like pin in $1 that nothing watches.
#
# Two ways a pin is watched, and both are answered by the thing that would do the
# watching rather than by a pattern resembling it:
#
#   - an action reference pinned to a sha with a trailing version comment, which
#     Renovate's built-in github-actions manager reads;
#   - a line the configured customManagers actually matched, per $2.
#
# Pins are detected on the comment-STRIPPED view: a version inside a comment is a
# mention, not a pin. Coverage is decided on the raw view, upstream. Reading one
# view for both is how a gate accepts a pin whose trailing comment merely
# mentions renovate.
scan_unwatched() {
  local file="$1" covered_file="$2"
  awk -v fname="$file" -v covered_file="$covered_file" '
    BEGIN {
      # "path:line" per covered pin, from the coverage reporter.
      while ((getline entry < covered_file) > 0) {
        n = split(entry, parts, ":")
        if (n >= 2 && parts[1] == fname) covered[parts[n] + 0] = 1
      }
      close(covered_file)
    }
    NR == FNR { code[FNR] = $0; next }
    {
      raw  = $0
      line = code[FNR]

      # An action pinned to a sha with a version comment is read by the built-in
      # github-actions manager. That version lives in the comment, so this one is
      # matched against the raw line by design.
      if (raw ~ /uses:[[:space:]]*[^[:space:]]+@[0-9a-f]{40}[[:space:]]*#[[:space:]]*v?[0-9]/) next

      # A floating action tag names a moving target rather than a version, so
      # there is no pin here for anything to watch. It is a supply-chain defect
      # and the zizmor job rejects it; reporting it here as an unwatched PIN
      # would name the wrong problem to whoever reads this gate.
      if (raw ~ /uses:[[:space:]]*[^[:space:]]+@v?[0-9]+[[:space:]]*$/) next

      if (line ~ /[^0-9A-Za-z.](v[0-9]+\.[0-9]+|[0-9]+\.[0-9]+\.[0-9]+)/ && !(FNR in covered)) {
        print fname ":" FNR ": " raw
      }
    }
  ' <(awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$file") "$file"
}

# A two-component number counts as a version only with a `v` — `v2.12` is the
# form golangci-lint-action takes, while a bare `2.12` is as likely a licence id
# (Apache-2.0), a ratio or a date fragment. Three components need no prefix.
#
# scan_versions prints one line per version-like token in $1, watched or not,
# ignoring comments. Used for the files asserted to carry none: a version named
# in prose is a mention, and failing on one would push the next author to delete
# the sentence rather than the pin.
scan_versions() {
  local file="$1"
  awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$file" |
    grep -nE '(^|[^0-9A-Za-z.])(v[0-9]+\.[0-9]+|[0-9]+\.[0-9]+\.[0-9]+)' || true
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
  local tmp covered out
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  covered="$tmp/covered"

  # A live config for the fixtures below, so the coverage reporter is exercised
  # rather than stubbed.
  cat >"$tmp/renovate.json" <<'CFG'
{
  "customManagers": [
    {
      "customType": "regex",
      "managerFilePatterns": ["/^.*\\.ya?ml$/"],
      "matchStrings": ["#\\s*renovate:\\s*datasource=(?<datasource>[a-z-]+)\\s+depName=(?<depName>[^\\s]+)[^\\n]*\\n[^\\n]*?(?<currentValue>v?[0-9]+\\.[0-9]+\\.[0-9]+[^\\s\"']*)"]
    }
  ]
}
CFG

  # A sha-pinned action with a version comment is watched by the built-in
  # github-actions manager, so no customManager needs to cover it.
  printf '      - uses: actions/checkout@%040d # v7.0.1\n' 0 >"$tmp/watched-action.yml"
  : >"$covered"
  [ -z "$(scan_unwatched "$tmp/watched-action.yml" "$covered")" ] ||
    self_test_die "reported a sha-pinned action with a version comment as unwatched"

  # A value pin the configured manager actually matches is watched — and the
  # coverage comes from running the manager, not from a pattern resembling it.
  printf '          # renovate: datasource=github-releases depName=golangci/golangci-lint\n          version: v2.13.1\n' >"$tmp/watched-value.yml"
  renovate_covered_lines "$tmp/renovate.json" "$tmp/watched-value.yml" >"$covered" ||
    self_test_die "the coverage reporter refused a config and a file that plainly match"
  grep -q ':2$' "$covered" ||
    self_test_die "the manager covers the pin on line 2 and the reporter said otherwise: $(cat "$covered")"
  [ -z "$(scan_unwatched "$tmp/watched-value.yml" "$covered")" ] ||
    self_test_die "reported a pin the configured manager matches as unwatched"

  # The same pin with nothing covering it is not.
  printf '          version: v2.13.1\n' >"$tmp/unwatched.yml"
  : >"$covered"
  [ -n "$(scan_unwatched "$tmp/unwatched.yml" "$covered")" ] ||
    self_test_die "accepted a value pin that nothing watches"

  printf '        run: |\n          go install golang.org/x/vuln/cmd/govulncheck@v1.1.4\n' >"$tmp/unwatched-install.yml"
  [ -n "$(scan_unwatched "$tmp/unwatched-install.yml" "$covered")" ] ||
    self_test_die "accepted an unannotated go install pin"

  # Coverage is per pin, not per file. The manager matches the annotated pin and
  # nothing beneath it, so the two loose versions below stay unwatched.
  printf '          # renovate: datasource=pypi depName=zizmor\n          pipx install zizmor==1.16.3\n          version: v9.9.9\n          version: v8.8.8\n' >"$tmp/scope.yml"
  renovate_covered_lines "$tmp/renovate.json" "$tmp/scope.yml" >"$covered" ||
    self_test_die "the coverage reporter refused a file the manager matches"
  out="$(scan_unwatched "$tmp/scope.yml" "$covered")"
  case "$out" in
    *v9.9.9*) ;;
    *) self_test_die "one covered pin vouched for every version beneath it: $out" ;;
  esac
  case "$out" in
    *zizmor* | *1.16.3*) self_test_die "the pin the manager actually matched was reported as unwatched: $out" ;;
  esac

  # A version appearing only inside a comment is a mention, not a pin.
  printf '          # bumped past v9.9.9 in the changelog\n          image: alpine\n' >"$tmp/mention.yml"
  : >"$covered"
  [ -z "$(scan_unwatched "$tmp/mention.yml" "$covered")" ] ||
    self_test_die "a version mentioned in a comment was reported as an unwatched pin"

  # The no-version assertion detects a version appearing in an exempted file.
  printf 'tasks:\n  build:\n    cmds:\n      - go build ./...\n' >"$tmp/clean.yml"
  [ -z "$(scan_versions "$tmp/clean.yml")" ] ||
    self_test_die "found a version in a file that carries none"

  printf 'image: alpine:3.21.0\n' >"$tmp/dirty.yml"
  [ -n "$(scan_versions "$tmp/dirty.yml")" ] ||
    self_test_die "a version appearing in a no-version file went undetected"

  # ── the coverage reporter's own failure modes ──
  #
  # These are the ones that matter most, because each of them previously produced
  # a full "everything is covered" answer.
  printf '{"customManagers": []}\n' >"$tmp/empty-renovate.json"
  ! renovate_covered_lines "$tmp/empty-renovate.json" "$tmp/watched-value.yml" >/dev/null 2>&1 ||
    self_test_die "reported coverage from a config declaring no customManagers"

  printf '{"customManagers": [{"matchStrings": ["renovate: NOTHING-MATCHES-THIS (?<currentValue>zzz)"]}]}\n' >"$tmp/dead-renovate.json"
  ! renovate_covered_lines "$tmp/dead-renovate.json" "$tmp/watched-value.yml" >/dev/null 2>&1 ||
    self_test_die "a customManager matching nothing reported coverage; a dead rule reads the same as a live one"

  printf '{"customManagers": [{"customType": "regex", "managerFilePatterns": ["x"], "matchStrings": ["(?<currentValue>"]}]}\n' >"$tmp/broken-renovate.json"
  ! renovate_covered_lines "$tmp/broken-renovate.json" "$tmp/watched-value.yml" >/dev/null 2>&1 ||
    self_test_die "reported coverage from a matchString that does not compile"

  # ── the config's own shape ──
  #
  # This gate reads renovate.json, so a manager Renovate would discard still
  # looks like coverage here. Each of these is a manager that watches nothing in
  # production while reading as a live rule.
  printf '{"customManagers": [{"matchStrings": ["renovate: (?<currentValue>v1)"]}]}\n' >"$tmp/notype-renovate.json"
  ! renovate_covered_lines "$tmp/notype-renovate.json" "$tmp/watched-value.yml" >/dev/null 2>&1 ||
    self_test_die "accepted a customManager with no customType, which Renovate ignores"

  printf '{"customManagers": [{"customType": "regex", "matchStrings": ["renovate: (?<currentValue>v1)"]}]}\n' >"$tmp/nopattern-renovate.json"
  ! renovate_covered_lines "$tmp/nopattern-renovate.json" "$tmp/watched-value.yml" >/dev/null 2>&1 ||
    self_test_die "accepted a customManager with no managerFilePatterns, which Renovate applies to no file"

  printf '{"customManagers": "not-a-list"}\n' >"$tmp/badtype-renovate.json"
  ! renovate_covered_lines "$tmp/badtype-renovate.json" "$tmp/watched-value.yml" >/dev/null 2>&1 ||
    self_test_die "accepted a customManagers key of the wrong type"

  printf 'not json at all\n' >"$tmp/notjson-renovate.json"
  ! renovate_covered_lines "$tmp/notjson-renovate.json" "$tmp/watched-value.yml" >/dev/null 2>&1 ||
    self_test_die "accepted a renovate.json that is not JSON"

  echo "check-version-pins self-test passed: it rejects unwatched pins, per-file over-reach, comment-only mentions, a version in an exempt file, and a renovate.json that is empty, dead, uncompilable, untyped, patternless, mistyped or not JSON."
}

self_test

fail=0
watched_files=0
watched_pins=0

# Coverage is computed once, over every watched file, by running the configured
# managers. A config the reporter cannot use stops the run rather than being
# reported as a clean tree.
covered_lines_file="$(mktemp)"
trap 'rm -f "$covered_lines_file"' EXIT

watched_paths=()
for glob in "${WATCHED_GLOBS[@]}"; do
  for file in $glob; do
    [ -f "$file" ] || continue
    [ "$file" = "go.mod" ] && continue
    watched_paths+=("$file")
  done
done

if [ "${#watched_paths[@]}" -eq 0 ]; then
  echo "error: the watched globs matched no files — the enumeration is broken, not the tree." >&2
  exit 2
fi

if ! renovate_covered_lines renovate.json "${watched_paths[@]}" >"$covered_lines_file"; then
  echo "::error::renovate.json cannot be applied to the watched files, so nothing can be said about which pins are watched" >&2
  exit 2
fi

for glob in "${WATCHED_GLOBS[@]}"; do
  for file in $glob; do
    [ -f "$file" ] || continue
    watched_files=$((watched_files + 1))
    # go.mod is read wholesale by Renovate's gomod manager, so every version in
    # it is watched by construction.
    [ "$file" = "go.mod" ] && continue
    # The denominator, per pin rather than per file: a file with every pin
    # watched and a file the scanner could not read produce the same silence.
    # Counted per PIN, not per line. grep -c counts matching LINES, so two pins
    # on one line raise the denominator by one and a gate reporting "20 tokens"
    # would be describing 19. -o prints each match.
    watched_pins=$((watched_pins + $(grep -oE '(^|[^0-9A-Za-z.])(v[0-9]+\.[0-9]+|[0-9]+\.[0-9]+\.[0-9]+)' "$file" | wc -l | tr -d ' ')))
    unwatched=$(scan_unwatched "$file" "$covered_lines_file")
    if [ -n "$unwatched" ]; then
      echo "::error::${file}: version pin(s) nothing can bump — add a '# renovate: datasource=... depName=...' comment above each:" >&2
      printf '%s\n' "$unwatched" >&2
      fail=1
    fi
  done
done

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

# ─── the exemptions must be asserted, not described ───
#
# The no-version classification is already an assertion: a listed file that
# acquires a version fails above. The other half is the one that rots toward
# permissive — a listed file that has nothing to say.
for file in "${NO_VERSION_FILES[@]}"; do
  [ -f "$file" ] || continue
  if [ ! -s "$file" ]; then
    echo "::error::${file} is classified as carrying no version but is empty; the entry asserts nothing" >&2
    fail=1
  fi
done

if [ "$watched_pins" -eq 0 ]; then
  echo "::error::${watched_files} watched file(s) read and not one version-shaped token found — the scanner is broken, not the tree." >&2
  exit 2
fi

if [ "$fail" -ne 0 ]; then
  echo "== version-pin coverage NOT met =="
  exit 1
fi
printf 'ok: %s version-shaped token(s) across %s watched file(s), every pin watched by a manager that was RUN; %s file(s) asserted to carry no version\n' \
  "$watched_pins" "$watched_files" "${#NO_VERSION_FILES[@]}"
