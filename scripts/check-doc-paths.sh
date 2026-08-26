#!/usr/bin/env bash
# shellcheck disable=SC2016  # single-quoted $ here belongs to awk, not the shell
#
# check-doc-paths.sh — every repo-relative path named in markdown must exist.
#
# Prose that names a file, a directory or a script is making a claim about this
# repository. The claim is true when written and nothing keeps it true: the next
# rename leaves a confident false statement with no tell, and the reader who
# follows it finds nothing and cannot tell whether the path moved or the feature
# was never there.
#
# This is the "named things resolve" documentation rule made executable, which is
# the only form of it that survives an unrelated edit.
#
# Scope is stated on extract_paths below and is narrower than the sentence above:
# markdown link targets, and file claims written as code spans. Directory claims
# are out, with the reason given there. The exclusions are listed one per line
# with a reason rather than folded into one pattern, because a pattern that
# quietly matches less is how this kind of check goes silent.
#
# Usage: scripts/check-doc-paths.sh

set -euo pipefail



repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

# shellcheck disable=SC1091  # resolved at run time from repo_root, not at parse time
. "${repo_root}/scripts/lib/tracked-files.sh"

require_tools grep sed awk find git || exit 2

# extract_paths prints one repo-relative FILE path per line from the markdown file
# $1, as "line:path".
#
# Scope, stated rather than implied. A span counts as a claim about this
# repository only when it contains a slash AND ends in a source extension this
# repo uses. That is narrower than "every path named in prose", deliberately:
#
#   - A bare filename (`iam.go`) is not distinguishable from a reference to a
#     file in some other tree, and this repo writes both.
#   - A slash without an extension is far more often a Go import path
#     (`github.com/nanohype/cloudgov`, `testify/mock`), a CIDR (`0.0.0.0/0`) or a
#     URL fragment than a directory in this tree.
#
# Directory claims are therefore NOT checked. That is a real gap, not a design
# choice: a renamed directory named only as `internal/output/` passes here. What
# compensates is that this repo names directories alongside the files in them,
# and those files are checked. Narrowing the rule is the alternative to a rule
# that produces false failures, which is worse — a gate that cries wolf gets its
# exclusions widened until it matches nothing.
# repo_extensions prints the alternation of every file extension present in this
# tree, for the span test below.
#
# DERIVED, NOT LISTED. A hand-written set of extensions has the same shape as a
# hand-written set of language constructs: right when written, silently missing
# the next file type added, and prose naming that file then goes unchecked. The
# list here named go, sh, md, yaml, json, awk, py, txt and html; this repo also
# carries go.mod and go.sum, both named in prose and neither checked.
repo_extensions() {
  tracked_files . |
    sed -n 's/.*\.\([A-Za-z0-9][A-Za-z0-9]*\)$/\1/p' |
    sort -u |
    tr '\n' '|' |
    sed 's/|$//'
}

# $2 optionally overrides the extension set. The self-test passes a FIXED set:
# its fixtures name .go and .sh paths, and deriving the set from the tree makes
# the self-test's answer depend on what the tree happens to contain — on a tree
# with no Go files the fixture stops being a path claim and the assertion fails
# for a reason that has nothing to do with the extractor. A self-test's fixture
# must lie inside the population the assertion is about.
extract_paths() {
  local file="$1" exts="${2:-}"
  [ -n "$exts" ] || exts="$(repo_extensions)"
  if [ -z "$exts" ]; then
    echo "extract_paths: no file extensions found in this tree; every code span would be out of scope" >&2
    return 1
  fi
  awk -v exts="$exts" '
    {
      line = $0

      # Markdown link targets are path claims too, and they are the ones a reader
      # actually clicks. `[the contract](AGENTS.md)` names a file exactly as
      # `AGENTS.md` in backticks does, and skipping it left the most followed
      # references unchecked.
      rest = line
      while (match(rest, /\]\([^)]+\)/)) {
        target = substr(rest, RSTART + 2, RLENGTH - 3)
        rest = substr(rest, RSTART + RLENGTH)
        if (target ~ /^#/) continue
        candidates[++cn] = target
        linked[cn] = 1
      }

      n = split(line, parts, "`")
      # Odd-indexed parts (2, 4, ...) are the spans between backticks.
      for (i = 2; i <= n; i += 2) {
        candidates[++cn] = parts[i]
      }

      for (ci = 1; ci <= cn; ci++) {
        span = candidates[ci]
        is_link = (ci in linked)
        delete candidates[ci]
        delete linked[ci]

        if (span ~ /[[:space:]]/) continue               # prose, not a path
        # A link target is a path by POSITION, so it needs neither a slash nor a
        # known extension to be a claim — `[the contract](AGENTS.md)` and
        # `[the licence](LICENSE)` both name a file. A backtick span needs both,
        # because there a bare word is not distinguishable from prose.
        if (!is_link) {
          if (span !~ /\//) continue
          if (span !~ ("\\.(" exts ")$")) continue
        }

        if (span ~ /^https?:/) continue                  # a URL
        if (span ~ /^[$~]/) continue                     # a variable or a home path
        if (span ~ /^\//) continue                       # absolute: another tree
        if (span ~ /^\.\//) sub(/^\.\//, "", span)       # ./x names x
        if (span ~ /\*/) continue                        # a glob
        if (span ~ /[<>]/) continue                      # a <placeholder>
        if (span ~ /@/) continue                         # a module or action ref
        if (span ~ /:[0-9]/) continue                    # file:line citation

        # A first segment carrying a dot, WHEN THERE ARE FURTHER SEGMENTS, is a
        # domain — so the span is an import path rather than a path in this tree.
        # The multi-segment condition is load-bearing: without it a single-segment
        # filename like AGENTS.md reads as a bare domain and is dropped, which is
        # how link targets to root-level files went unchecked.
        if (span ~ /\//) {
          split(span, seg, "/")
          if (seg[1] ~ /\./ && seg[1] !~ /^\.[a-z]/) continue
        }

        print FNR ":" span
      }
      cn = 0
    }
  ' "$file"
}

# ── Why this script self-tests ────────────────────────────────────────────────
#
# It is a pattern over prose, which is the shape that silently stops matching.
# A version of it that extracted nothing would report every document as clean.
self_test_die() {
  echo "check-doc-paths self-test FAILED: $*" >&2
  echo "The gate could not be shown to reject, so its pass is not evidence." >&2
  exit 1
}

readonly SELF_TEST_EXTS='go|sh|md|yaml|yml|json|awk|py|txt|html'

self_test() {
  local tmp found want excluded
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  cat >"$tmp/doc.md" <<'MD'
See `internal/cloud/aws/iam.go` for the provider.
Run `scripts/coverage.sh` to check the floors.
The URL `https://example.test/a/b` is not a path.
A flag like `--output-file` is not a path.
A placeholder `<app>/chart/Chart.yaml` is not a claim about this repo.
An absolute path `/etc/hosts` belongs to the machine, not the repo.
A module ref `example.com/x@v1.2.3` is not a path.
A citation `cmd/root.go:59` names a line, not a file to stat.
MD

  found="$(extract_paths "$tmp/doc.md" "$SELF_TEST_EXTS")"

  printf '%s\n' "$found" | grep -q 'internal/cloud/aws/iam.go' ||
    self_test_die "a plain repo-relative path was not extracted"
  printf '%s\n' "$found" | grep -q 'scripts/coverage.sh' ||
    self_test_die "a script path was not extracted"

  for excluded in 'https://' '--output-file' '<app>' '/etc/hosts' '@v1.2.3' 'root.go:59' 'example.com'; do
    if printf '%s\n' "$found" | grep -qF -- "$excluded"; then
      self_test_die "extracted ${excluded}, which is out of scope and would produce a false failure"
    fi
  done

  # The line number must name the line the path is on, not the position in the
  # extracted list. A citation that points at the wrong line sends the reader to
  # prose that is fine.
  case "$(printf '%s\n' "$found" | grep 'coverage.sh')" in
    2:*) ;;
    *) self_test_die "scripts/coverage.sh is on line 2 and was cited elsewhere: $(printf '%s\n' "$found" | grep 'coverage.sh')" ;;
  esac

  # ── the escape surface, probed rather than reasoned about ──
  #
  # A markdown link target is what a reader actually clicks, and it needs neither
  # a slash nor an extension to be a claim about this repository.
  cat >"$tmp/links.md" <<'MD'
See [the agent contract](AGENTS.md) and [the licence](LICENSE).
An [external link](https://example.test/a) is not a path.
An [anchor](#section) is not a path.
A [nested one](internal/cloud/aws/iam.go) is.
MD
  found="$(extract_paths "$tmp/links.md" "$SELF_TEST_EXTS")"
  for want in 'AGENTS.md' 'LICENSE' 'internal/cloud/aws/iam.go'; do
    printf '%s
' "$found" | grep -q "$want" ||
      self_test_die "a markdown link target was not extracted: $want (got: $found)"
  done
  for excluded in 'https://' '#section'; do
    if printf '%s
' "$found" | grep -qF -- "$excluded"; then
      self_test_die "extracted ${excluded} from a link target, which is out of scope"
    fi
  done

  # A bare word in backticks is still out of scope: there, unlike in link
  # position, a name is not distinguishable from prose.
  printf 'The word `LICENSE` appears in running text.
' >"$tmp/bareword.md"
  # Captured, then tested. `[ -z "$(producer ...)" ]` cannot tell a producer that
  # FOUND nothing from one that PRODUCED nothing: an absent tool or a broken
  # helper yields empty, and empty is the passing value here. The assignment
  # carries the status; the test carries the answer.
  probe_0="$(extract_paths "$tmp/bareword.md" "$SELF_TEST_EXTS")" || self_test_die "extract_paths could not run, so an empty result here would be a failure reported as a clean fixture"
  [ -z "$probe_0" ] ||
    self_test_die "a bare word in backticks was treated as a path claim"

  # The extension set is derived from the tree, so the derivation needs its own
  # control: an empty or wrong set silently puts every code span out of scope,
  # and the gate then reports every document clean.
  case "|$(repo_extensions)|" in
    *"|sh|"*) ;;
    *) self_test_die "the derived extension set omits sh, and this tree contains shell scripts; the derivation has stopped reading the tree" ;;
  esac
  case "|$(repo_extensions)|" in
    *"|zzmadeup|"*) self_test_die "the derived extension set contains an extension no file in this tree uses" ;;
  esac

  # A document naming no paths must extract nothing rather than something.
  printf 'Prose with no code spans at all.\n' >"$tmp/bare.md"
  probe_1="$(extract_paths "$tmp/bare.md" "$SELF_TEST_EXTS")" || self_test_die "extract_paths could not run, so an empty result here would be a failure reported as a clean fixture"
  [ -z "$probe_1" ] ||
    self_test_die "extracted a path from a document that names none"

  echo "check-doc-paths self-test passed: it extracts repo paths and markdown link targets, skips URLs, anchors, flags, placeholders, citations and bare words, and cites the right line."
}

# The enumeration's precondition, named before anything depends on it. Without
# this the silent filesystem fallback restores the behaviour the tracked set
# replaced, and a small count is the only sign.
require_tracked_source "$repo_root" "check-doc-paths" || exit 2

self_test

fail=0
checked=0
claims=0

while IFS= read -r doc; do
  checked=$((checked + 1))
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    claims=$((claims + 1))
    line="${entry%%:*}"
    path="${entry#*:}"
    if [ ! -e "$path" ]; then
      echo "::error::${doc}:${line}: names \`${path}\`, which does not exist" >&2
      fail=1
    fi
  done < <(extract_paths "$doc")
done < <(tracked_files . -name '*.md' -type f | sort)

md_list=$(mktemp)
trap 'rm -f "$md_list"' EXIT
tracked_files . -name '*.md' -type f | sed 's|^\./||' >"$md_list" || true
outside_scripts=$(grep -cv '^scripts/' "$md_list" || true)

# A verdict over nothing is not a pass. Both counts matter: no documents means
# the enumeration broke, and no claims means the extractor stopped matching —
# and either would report a clean tree.
#
# A FLOOR WELL UNDER THE REAL COUNT, not at-least-one. "Matched almost nothing"
# is the failure that reads as success: an at-least-one floor is satisfied by the
# gate scripts themselves, or by one stray file, and reports a clean tree. This
# catches an enumeration that collapsed, and is set low enough that ordinary
# growth or deletion does not trip it.
# UNCONDITIONAL: at least one document outside this gate's own directories. See
# the note in check-context.sh — a count cannot tell the repo's own files from
# the gate's, and only this half can.
if [ "${outside_scripts:-0}" -eq 0 ]; then
  echo "error: every markdown file read lies under scripts/, so nothing about this repository's" >&2
  echo "       documentation was examined. That is an empty answer, not a clean one." >&2
  exit 2
fi

readonly DOC_FILE_FLOOR=4   # measured 5 markdown files
readonly DOC_CLAIM_FLOOR=15 # measured 23 path claims
# The default is the FAILING value, and that direction is the fix. An empty
# operand to a numeric test exits 2 with "integer expected", and in an `if` a 2
# reads as false — so the floor is not evaluated to false, it is SKIPPED, and the
# skip looks exactly like a pass. Defaulting to 0 would be the defect written
# into its own fix: 0 is a clean count and is what an absent tool most resembles.
if [ "${checked:--1}" -lt "$DOC_FILE_FLOOR" ]; then
  echo "error: read ${checked} markdown file(s), under the floor of ${DOC_FILE_FLOOR} — the enumeration collapsed." >&2
  exit 2
fi
if [ "${claims:--1}" -lt "$DOC_CLAIM_FLOOR" ]; then
  echo "error: extracted ${claims} path claim(s) from ${checked} file(s), under the floor of ${DOC_CLAIM_FLOOR} — the extractor stopped matching." >&2
  exit 2
fi

if [ "$fail" -ne 0 ]; then
  echo "== documented paths NOT met =="
  exit 1
fi
printf 'ok: %s path claim(s) across %s markdown file(s) all resolve\n' "$claims" "$checked"
