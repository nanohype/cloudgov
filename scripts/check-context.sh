#!/usr/bin/env bash
#
# check-context.sh — enforce that every cloud call threads the signal-aware context.
#
# CLAUDE.md: "Every cloud API call takes a context.Context, derived from
# cmd.Context() in handlers — never context.Background()." The root command roots
# that context in one cancelled on the first SIGINT/SIGTERM, so a call that starts
# from a fresh background context severs the chain and an interrupt can no longer
# unwind it.
#
# The single legitimate detached context in the tree is the signal-context
# bootstrap in Execute(): signal.NotifyContext(context.Background(), ...). That is
# the call that *creates* the chain, so it is the one place allowed to start one.
#
# Tests are exempt. A test has no cobra command to inherit from, and
# context.Background() is the correct root for one.
#
# ── Why this script self-tests ────────────────────────────────────────────────
#
# An earlier version of this check scanned only `cmd/` and only for the literal
# string "context.Background()". It therefore could not see context.TODO()
# anywhere, nor either spelling under internal/ — where all the cloud calls
# actually live. It reported "check passed" against a tree with planted
# violations in both directories, because the probe could not return a positive
# for the thing it claimed to test.
#
# A gate that has never been observed to fail is not evidence of anything. So
# this one proves it can fail before it is allowed to report a pass: it plants
# known violations in a scratch tree, asserts the plant landed, and requires the
# scan to catch every one. If the self-test cannot make the gate go red, the gate
# does not get to say green.
#
# Run locally the same way CI does: scripts/check-context.sh
set -euo pipefail

lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/lib" && pwd)"

# scan_tree prints one "path:line:content" per offending occurrence under $1, or
# nothing. Both detached-context spellings are matched; _test.go files and the
# single signal.NotifyContext bootstrap are excluded.
#
# Comments and string bodies are stripped before matching, and that is
# load-bearing in both directions. A detached context is a CALL, so a token inside
# a string literal is a mention rather than an occurrence, and matching one is a
# false positive. Excluding on a comment is worse: it fails the gate OPEN, because
# a real `context.Background()` whose line carries a trailing comment mentioning
# the allowed bootstrap gets filtered out as if it were the bootstrap. A gate that
# reads comments as code fails in exactly the case it exists for.
#
# THE ESCAPE SURFACE, ENUMERATED. This matches text, so forms that mean the same
# thing to the compiler and differ on the line evade it. Probed by running them:
#
#   `context . Background ( )`     — legal Go, evades. gofmt normalises it, and
#                                     CI runs gofmt through golangci-lint's
#                                     formatter, so a file reaching this gate is
#                                     already normalised. That is a dependency on
#                                     another gate, stated rather than assumed.
#   a call split across lines      — same, and same normalisation.
#   `b := context.Background; b()` — evades. Nothing in the tree does this and a
#                                     text matcher cannot follow a value; the
#                                     durable form is a go/types resolution, which
#                                     this shell gate is the wrong shape for.
#   an aliased import              — CLOSED below, by reading the binding per file.
#
# The trailing `|| true` on the pipeline is deliberate: grep exits 1 on "no
# matches", which under `set -e` would abort the script on the *success* case.
scan_tree() {
  local root="$1" file stripped alias decommented
  while IFS= read -r file; do
    case "$file" in *_test.go) continue ;; esac
    # The stripper's status is tested here rather than left to `set -e`. A
    # function whose own status is read — `out=$(scan_tree x) || die` — runs with
    # errexit suppressed throughout, so a failing command inside this loop would
    # not abort it and the file would simply contribute no lines. That turns a
    # stripper that cannot read a file into a file with nothing to report.
    # The IMPORT BLOCK, taken by position rather than by pattern.
    #
    # No text view answers this. The import path is string content, so blanking
    # strings erases the alias; keeping strings admits any line in the file that
    # happens to end in `"context"` — a raw string literal spanning lines does
    # exactly that, and a comment did before it. Both are the same mistake: asking
    # a whole-file matcher a question that is only about one region.
    #
    # Go permits one `import` block or several, each `import "path"` or
    # `import ( ... )`. Everything after the first non-import top-level
    # declaration is code, and an alias cannot be declared there.
    if ! decommented=$(awk -v style=go -f "${lib_dir}/strip-comments.awk" "$file"); then
      echo "scan_tree: the comment stripper failed on ${file}; this file was not examined" >&2
      return 1
    fi
    imports=$(printf '%s\n' "$decommented" | awk '
      /^import[[:space:]]*\(/ { inblock = 1; next }
      inblock && /^\)/        { inblock = 0; next }
      inblock                  { print; next }
      /^import[[:space:]]/     { print; next }
      /^(func|type|var|const)[[:space:]]/ { exit }
    ')
    if ! stripped=$(awk -v style=go -v strings=blank -f "${lib_dir}/strip-comments.awk" "$file"); then
      echo "scan_tree: the comment stripper failed on ${file}; this file was not examined" >&2
      return 1
    fi

    # The name the context package is bound to IN THIS FILE. A file importing it
    # under an alias calls `ctxpkg.Background()`, which a pattern hardcoding
    # "context." does not match at all — an escape that needs no intent, just an
    # import line.
    #
    # Read from the COMMENT-STRIPPED view with strings intact — a third view,
    # distinct from both the raw file and the string-blanked one the matcher uses.
    #
    # The import PATH is string content, so `strings=blank` empties it and no
    # alias is ever found. The raw file is wrong in the other direction, and
    # worse: any indented line ending in `"context"` binds the alias, INCLUDING
    # one inside a block comment. A file carrying such a comment resolves its
    # alias to a name nothing calls, the matcher greps for a method on that name,
    # and every detached context in that file goes unreported. Reading the raw
    # file to avoid one blanking bug reintroduced the comment-reading bug this
    # gate exists to prevent, one layer up from the exclusion that had it.
    # Four spellings bind the package, and only two of them carry an alias:
    #
    #   import "context"           -> context     (the `import` keyword is not a name)
    #   import ctxpkg "context"    -> ctxpkg
    #       "context"              -> context     (inside a parenthesised block)
    #       ctxpkg "context"       -> ctxpkg
    #
    # Reading the token before the path without dropping the keyword binds the
    # alias to `import`, and `import.Background()` matches nothing — which is how
    # this closure regressed the plain case while fixing the aliased one. The
    # floor caught it.
    alias=$(
      # `import ctxpkg "context"` — a single-line aliased import.
      sed -nE 's/^[[:space:]]*import[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+"context"[[:space:]]*$/\1/p' <<<"$imports"
      # `    ctxpkg "context"` — an aliased import inside a block. The `import`
      # keyword is excluded explicitly rather than by pattern shape, because an
      # optional-group spelling binds the alias to the keyword on the plain
      # `import "context"` line and matches nothing thereafter.
      sed -nE 's/^[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+"context"[[:space:]]*$/\1/p' <<<"$imports" |
        grep -v '^import$' || true
    )
    alias=$(printf '%s\n' "$alias" | grep -v '^$' | head -1)
    [ -n "$alias" ] || alias="context"

    printf '%s\n' "$stripped" \
      | grep -nE "${alias}\\.(Background|TODO)\\(\\)" \
      | grep -v "signal\\.NotifyContext(${alias}\\.Background()" \
      | sed "s|^|${file}:|" \
      || true
  done < <(find "$root" -name '*.go' -type f 2>/dev/null | sort)
}

# ── observing the scanner, rather than only its output ────────────────────────
#
# A command substitution discards the status of what ran inside it. That is
# harmless for a control expecting output and silently wrong for one expecting
# none: `[[ -n "$(scan_tree "$tmp")" ]]` is false when the scanner FOUND NOTHING
# and equally false when the scanner DIED before printing, so a negative control
# written that way reports success for a scanner that cannot look at all.
#
# The status has to be read where it can still be acted on. Inside a
# substitution even an exit only leaves the subshell, so the assignment is the
# last place the failure is visible.
scan_or_die() {
  local root="$1" out
  out=$(scan_tree "$root") ||
    die "the scanner failed on ${root}; its output cannot answer whether anything is reported there"
  printf '%s' "$out"
}

# reports_nothing / reports succeed on the captured text, never on a pipeline.
reports() {
  printf '%s\n' "$1" | grep -qF -- "$2"
}

die() {
  echo "check-context self-test FAILED: $*" >&2
  echo "The gate could not be shown to work, so its result is not trustworthy." >&2
  exit 1
}

# self_test builds a scratch tree, plants one violation of each shape the gate is
# supposed to catch, and requires the scan to catch all of them — then requires a
# clean tree to come back silent, so the gate is not simply always-red.
self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mkdir -p "$tmp/cmd" "$tmp/internal/cloud/aws"

  # The allowed bootstrap, plus a compliant handler. Neither may be flagged.
  cat >"$tmp/cmd/root.go" <<'CLEAN'
package cmd

func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_ = ctx
}

func runScan(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	_ = ctx
	return nil
}
CLEAN

  # A test file using context.Background() is legitimate and must stay silent.
  cat >"$tmp/internal/cloud/aws/aws_test.go" <<'CLEANTEST'
package aws

func TestThing(t *testing.T) {
	_ = context.Background()
}
CLEANTEST

  clean_scan="$(scan_or_die "$tmp")"
  if [[ -n "$clean_scan" ]]; then
    die "a compliant tree was flagged (false positive): $clean_scan"
  fi

  # Now plant one violation per shape. Each entry is "relative/path.go|needle".
  local plants=(
    "cmd/bad_background.go|context.Background()"
    "cmd/bad_todo.go|context.TODO()"
    "internal/cloud/aws/bad_background.go|context.Background()"
    "internal/cloud/aws/bad_todo.go|context.TODO()"
  )

  local entry path needle found
  for entry in ${plants[@]+"${plants[@]}"}; do
    path="${entry%%|*}"
    needle="${entry##*|}"

    printf 'package broken\n\nfunc scan() {\n\t_ = %s\n}\n' "$needle" >"$tmp/$path"

    # Assert the mutation actually landed. A plant that silently failed to write
    # looks exactly like a gate that failed to catch, and the two must never be
    # confused — that confusion is the whole reason this self-test exists.
    if ! grep -qF "$needle" "$tmp/$path"; then
      die "could not plant $needle into $path (mutation did not land)"
    fi

    found="$(scan_tree "$tmp")"
    if ! grep -qF "$path" <<<"$found"; then
      die "planted $needle in $path and the scan did not report it"
    fi

    rm -f "$tmp/$path"
  done

  # A real violation whose line carries a trailing comment mentioning the allowed
  # bootstrap. An exclusion that reads that comment filters the violation out,
  # which is the fail-open direction: the gate goes green on the exact shape it
  # exists to catch.
  cat >"$tmp/internal/cloud/aws/masked.go" <<'MASKED'
package aws

func masked() {
	ctx := context.Background() // not signal.NotifyContext(context.Background()
	_ = ctx
}
MASKED
  masked_scan="$(scan_or_die "$tmp")"
  if [[ -z "$masked_scan" ]]; then
    die "a violation whose line carries a comment mentioning the allowed bootstrap was not reported (the gate reads comments as code)"
  fi
  rm -f "$tmp/internal/cloud/aws/masked.go"

  # A violation sharing a line with a Go rune literal that contains an escaped
  # quote. `'\''` is one rune, and a stripper honouring backslash escapes only
  # inside DOUBLE quotes reads it as a closed string followed by an opening one —
  # then blanks the rest of the line as string body, deleting the call from the
  # view this gate matches against. The same violation split across two lines is
  # caught, so nothing else here would notice.
  cat >"$tmp/internal/cloud/aws/rune.go" <<'RUNE'
package aws

func runeLiteral(c byte) interface{} {
	if c == '\'' { return context.Background() }
	return nil
}
RUNE
  rune_scan="$(scan_or_die "$tmp")"
  if ! reports "$rune_scan" 'rune.go'; then
    die "a violation after a rune literal on the same line was not reported (the string state machine desynchronised on an escaped quote)"
  fi
  rm -f "$tmp/internal/cloud/aws/rune.go"

  # A file importing the context package under an alias. A pattern hardcoding
  # "context." matches nothing here, so the violation is invisible — and nothing
  # about writing it requires intent, only an import line.
  cat >"$tmp/internal/cloud/aws/aliased.go" <<'ALIASED'
package aws

import (
	ctxpkg "context"
)

func aliased() ctxpkg.Context {
	return ctxpkg.Background()
}
ALIASED
  aliased_scan="$(scan_or_die "$tmp")"
  if ! reports "$aliased_scan" 'aliased.go'; then
    die "a detached context reached through an aliased import was not reported"
  fi
  rm -f "$tmp/internal/cloud/aws/aliased.go"

  # The plain single-line import. Reading the token before the path without
  # excluding the `import` keyword binds the alias to it, and `import.Background()`
  # matches nothing — the alias closure regressed this while fixing the aliased
  # case, and only the positive-control harness noticed.
  cat >"$tmp/internal/cloud/aws/plainimport.go" <<'PLAIN'
package aws

import "context"

func plainImport() context.Context {
	return context.Background()
}
PLAIN
  plain_scan="$(scan_or_die "$tmp")"
  if ! reports "$plain_scan" 'plainimport.go'; then
    die "a detached context under a single-line 'import \"context\"' was not reported"
  fi
  rm -f "$tmp/internal/cloud/aws/plainimport.go"

  # And the complement: a file that binds some OTHER package to a name must not
  # have that name matched, or the alias handling becomes a false-positive engine.
  cat >"$tmp/internal/cloud/aws/otherpkg.go" <<'OTHER'
package aws

import (
	ctxpkg "example.com/notcontext"
)

func other() { _ = ctxpkg.Background() }
OTHER
  other_scan="$(scan_or_die "$tmp")"
  if reports "$other_scan" 'otherpkg.go'; then
    die "a Background() call on a package that is not context was flagged: $other_scan"
  fi
  rm -f "$tmp/internal/cloud/aws/otherpkg.go"

  # The complement, so the rule above cannot be satisfied by treating every
  # single quote as ordinary text: a rune literal that genuinely CONTAINS the
  # banned token is a character, not a call.
  cat >"$tmp/internal/cloud/aws/runeclean.go" <<'RUNECLEAN'
package aws

func quoteChar() byte {
	q := '\''
	return byte(q)
}
RUNECLEAN
  # ── an alias must not be readable out of a COMMENT ──
  #
  # The alias resolver decides which name the matcher greps for. If a block
  # comment can set it, one comment anywhere in a file silently disables the gate
  # for that whole file — the escape needs no intent, only a doc comment showing
  # an aliased import.
  cat >"$tmp/internal/cloud/aws/commentalias.go" <<'ALIAS'
package aws

import "context"

/*
	ctxpkg "context"
*/
func commentAlias() context.Context {
	return context.Background()
}
ALIAS
  # ── an alias must not be readable out of a RAW STRING either ──
  #
  # The same mistake as the comment case, one view over: taking the alias from a
  # view that KEEPS strings admits any line in the file ending in `"context"`,
  # and a raw string literal spans lines. Both are closed by reading the import
  # block by position rather than matching the whole file.
  cat >"$tmp/internal/cloud/aws/rawalias.go" <<'RAW'
package aws

import "context"

var doc = `
	ctxpkg "context"
`

func rawAlias() context.Context {
	return context.Background()
}
RAW
  rawalias_scan="$(scan_or_die "$tmp")"
  if ! reports "$rawalias_scan" 'rawalias.go'; then
    die "a detached context went unreported because a raw string literal set the import alias; the alias must come from the import block, not from a match anywhere in the file"
  fi
  rm -f "$tmp/internal/cloud/aws/rawalias.go"

  commentalias_scan="$(scan_or_die "$tmp")"
  if ! reports "$commentalias_scan" 'commentalias.go'; then
    die "a detached context went unreported because a block comment set the import alias; one such comment disables this gate for the file that carries it"
  fi
  rm -f "$tmp/internal/cloud/aws/commentalias.go"

  runeclean_scan="$(scan_or_die "$tmp")"
  if reports "$runeclean_scan" 'runeclean.go'; then
    die "a file whose only single quotes are a rune literal was flagged: $runeclean_scan"
  fi
  rm -f "$tmp/internal/cloud/aws/runeclean.go"

  # Removing every plant returns the tree to silent, so the gate tracks the tree
  # rather than latching red once it has fired.

  # The citation must name the line the violation is ON.
  #
  # This asserts the property rather than the mechanism. Comment bodies are
  # blanked rather than removed precisely so line numbers survive — but a later
  # refactor to joined text, or a pattern anchored with something that can cross
  # a newline, would shift every citation up by however many blanked lines sit
  # above the match. The gate would still go red, so a control that only checks
  # "does it reject" would pass while every file:line it prints points somewhere
  # else. A citation that names the wrong line is worse than none: it sends the
  # reader to code that is fine.
  cat >"$tmp/internal/cloud/aws/cited.go" <<'CITED'
package aws

/* a block comment
   spanning several lines
   so a crossing match has somewhere to land */

// and a line comment directly above
func cited() {
	ctx := context.Background()
	_ = ctx
}
CITED
  cited_scan="$(scan_or_die "$tmp")"
  citation="$(printf '%s\n' "$cited_scan" | grep -F 'cited.go' || true)"
  if [[ -z "$citation" ]]; then
    die "the violation in cited.go was not reported at all"
  fi
  cited_line="$(printf '%s' "$citation" | head -1 | cut -d: -f2)"
  if [[ "$cited_line" != "9" ]]; then
    die "the violation is on line 9 of cited.go and was cited at line ${cited_line}; the citation points at the wrong code"
  fi
  rm -f "$tmp/internal/cloud/aws/cited.go"

  # The stripper must preserve the shape of the file exactly: same number of
  # lines, and every line the same length. Line count is what keeps citations
  # pointing at the right line; line length is what keeps a column-sensitive
  # matcher — an anchor, a fixed-width field — reading the same position it would
  # have read in the source. Deleting comments instead of blanking them would
  # satisfy neither.
  cat >"$tmp/internal/cloud/aws/shape.go" <<'SHAPE'
package aws

/* a block comment
   over several lines */
func shape() string {
	s := "text // with a marker" // and a trailing comment
	return s
}
SHAPE
  shape_in="$(wc -l <"$tmp/internal/cloud/aws/shape.go" | tr -d ' ')"
  shape_out="$(awk -v style=go -v strings=blank -f "${lib_dir}/strip-comments.awk" "$tmp/internal/cloud/aws/shape.go" | wc -l | tr -d ' ')"
  if [[ "$shape_in" != "$shape_out" ]]; then
    die "stripping changed the line count ($shape_in -> $shape_out); every citation would be off by the difference"
  fi
  if ! diff -q \
    <(awk '{print length}' "$tmp/internal/cloud/aws/shape.go") \
    <(awk -v style=go -v strings=blank -f "${lib_dir}/strip-comments.awk" "$tmp/internal/cloud/aws/shape.go" | awk '{print length}') \
    >/dev/null; then
    die "stripping changed a line's length; a column-sensitive matcher would read a different position than the source has"
  fi
  rm -f "$tmp/internal/cloud/aws/shape.go"

  # A mention inside a comment or a string literal is not a call.
  cat >"$tmp/internal/cloud/aws/mentions.go" <<'MENTIONS'
package aws

// Handlers must not call context.Background(); they thread cmd.Context().
func mentions() string {
	/* context.TODO() is not allowed here either */
	return "context.Background()"
}
MENTIONS
  mention_scan="$(scan_or_die "$tmp")"
  if [[ -n "$mention_scan" ]]; then
    die "a mention in a comment or string literal was reported as a call: $mention_scan"
  fi
  rm -f "$tmp/internal/cloud/aws/mentions.go"

  residue_scan="$(scan_or_die "$tmp")"
  if [[ -n "$residue_scan" ]]; then
    die "tree still flagged after every plant was removed: $residue_scan"
  fi

  echo "context-awareness self-test passed: it catches Background() and TODO() under cmd/ and internal/, through an aliased import, past a rune literal, past a masking comment and past an alias named only in a comment or a raw string, cites the right line, and stays silent on compliant code, tests and foreign packages."
}

cd "$(dirname "$0")/.."

self_test

# The denominator. A gate that passes over zero files reads exactly like a gate
# that passed over all of them, and an --include glob or a find predicate that
# stops matching is the usual way that happens. Reporting the count makes an
# empty sweep visible rather than merely non-failing.
scanned=$(find . -name '*.go' -type f -not -path './.git/*' -not -name '*_test.go' | wc -l | tr -d ' ')
if [[ "$scanned" -eq 0 ]]; then
  echo "context-awareness check: no Go files found — the enumeration is broken, not the tree." >&2
  exit 2
fi

offenders="$(scan_tree .)"

if [[ -n "$offenders" ]]; then
  echo "context-awareness check failed: cloud calls must thread cmd.Context(), not a detached context." >&2
  echo "" >&2
  echo "$offenders" >&2
  echo "" >&2
  echo "Derive the context from cmd.Context() so SIGINT/SIGTERM cancels in-flight cloud calls." >&2
  echo "The only allowed detached context is the signal.NotifyContext base in Execute()." >&2
  echo "== context-awareness NOT met ==" >&2
  exit 1
fi

printf 'context-awareness check passed: %s non-test Go file(s) read, no detached contexts outside the signal bootstrap.\n' "$scanned"
