#!/usr/bin/env bash
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
# file claims written as code spans, not directory claims. The exclusions are
# listed one per line with a reason rather than folded into one pattern, because
# a pattern that quietly matches less is how this kind of check goes silent.
#
# Usage: scripts/check-doc-paths.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lib_dir="${repo_root}/scripts/lib"
cd "$repo_root"

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
extract_paths() {
  local file="$1"
  awk '
    {
      line = $0
      n = split(line, parts, "`")
      # Odd-indexed parts (2, 4, ...) are the spans between backticks.
      for (i = 2; i <= n; i += 2) {
        span = parts[i]

        if (span ~ /[[:space:]]/) continue               # prose, not a path
        if (span !~ /\//) continue                       # a bare name: out of scope
        if (span !~ /\.(go|sh|md|ya?ml|json|awk|py|txt|html)$/) continue

        if (span ~ /^https?:/) continue                  # a URL
        if (span ~ /^[$~]/) continue                     # a variable or a home path
        if (span ~ /^\//) continue                       # absolute: another tree
        if (span ~ /^\.\//) sub(/^\.\//, "", span)       # ./x names x
        if (span ~ /\*/) continue                        # a glob
        if (span ~ /[<>]/) continue                      # a <placeholder>
        if (span ~ /@/) continue                         # a module or action ref
        if (span ~ /:[0-9]/) continue                    # file:line citation

        # A first segment carrying a dot is a domain, so the span is an import
        # path rather than a path in this tree.
        split(span, seg, "/")
        if (seg[1] ~ /\./ && seg[1] !~ /^\.[a-z]/) continue

        print FNR ":" span
      }
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

self_test() {
  local tmp found
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

  found="$(extract_paths "$tmp/doc.md")"

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

  # A document naming no paths must extract nothing rather than something.
  printf 'Prose with no code spans at all.\n' >"$tmp/bare.md"
  [ -z "$(extract_paths "$tmp/bare.md")" ] ||
    self_test_die "extracted a path from a document that names none"

  echo "check-doc-paths self-test passed: it extracts repo paths, skips URLs, flags, placeholders and citations, and cites the right line."
}

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
done < <(find . -name '*.md' -not -path './.git/*' -type f | sort)

# A verdict over nothing is not a pass. Both counts matter: no documents means
# the enumeration broke, and no claims means the extractor stopped matching —
# and either would report a clean tree.
if [ "$checked" -eq 0 ]; then
  echo "error: no markdown files found — the enumeration is broken, not the tree." >&2
  exit 2
fi
if [ "$claims" -eq 0 ]; then
  echo "error: ${checked} markdown file(s) read and not one path claim extracted — the extractor is broken, not the docs." >&2
  exit 2
fi

if [ "$fail" -ne 0 ]; then
  echo "== documented paths do NOT all resolve =="
  exit 1
fi
printf 'ok: %s path claim(s) across %s markdown file(s) all resolve\n' "$claims" "$checked"
