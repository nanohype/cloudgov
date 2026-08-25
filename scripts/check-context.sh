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
# a string literal is a mention rather than an occurrence. Matching a comment would report a violation that is only a
# mention. Worse, EXCLUDING on a comment fails the gate open: a real
# `context.Background()` whose line carries a trailing comment mentioning
# `signal.NotifyContext(context.Background()` was filtered out as if it were the
# bootstrap. A gate that reads comments as code fails in exactly the case it
# exists for.
#
# The trailing `|| true` on the pipeline is deliberate: grep exits 1 on "no
# matches", which under `set -e` would abort the script on the *success* case.
scan_tree() {
  local root="$1" file stripped
  while IFS= read -r file; do
    case "$file" in *_test.go) continue ;; esac
    stripped=$(awk -v style=go -v strings=blank -f "${lib_dir}/strip-comments.awk" "$file")
    printf '%s\n' "$stripped" \
      | grep -nE 'context\.(Background|TODO)\(\)' \
      | grep -v 'signal\.NotifyContext(context\.Background()' \
      | sed "s|^|${file}:|" \
      || true
  done < <(find "$root" -name '*.go' -type f 2>/dev/null | sort)
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

  if [[ -n "$(scan_tree "$tmp")" ]]; then
    die "a compliant tree was flagged (false positive): $(scan_tree "$tmp")"
  fi

  # Now plant one violation per shape. Each entry is "relative/path.go|needle".
  local plants=(
    "cmd/bad_background.go|context.Background()"
    "cmd/bad_todo.go|context.TODO()"
    "internal/cloud/aws/bad_background.go|context.Background()"
    "internal/cloud/aws/bad_todo.go|context.TODO()"
  )

  local entry path needle found
  for entry in "${plants[@]}"; do
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

  # Removing every plant must return the tree to silent, proving the gate tracks
  # the tree rather than latching red once it has fired.
  # A real violation whose line carries a trailing comment mentioning the allowed
  # bootstrap. The exclusion used to read that comment and filter the violation
  # out, which is the fail-open direction: the gate went green on the exact shape
  # it exists to catch.
  cat >"$tmp/internal/cloud/aws/masked.go" <<'MASKED'
package aws

func masked() {
	ctx := context.Background() // not signal.NotifyContext(context.Background()
	_ = ctx
}
MASKED
  if [[ -z "$(scan_tree "$tmp")" ]]; then
    die "a violation whose line carries a comment mentioning the allowed bootstrap was not reported (the gate reads comments as code)"
  fi
  rm -f "$tmp/internal/cloud/aws/masked.go"

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
  citation="$(scan_tree "$tmp" | grep 'cited.go')"
  if [[ -z "$citation" ]]; then
    die "the violation in cited.go was not reported at all"
  fi
  cited_line="$(printf '%s' "$citation" | head -1 | cut -d: -f2)"
  if [[ "$cited_line" != "9" ]]; then
    die "the violation is on line 9 of cited.go and was cited at line ${cited_line}; the citation points at the wrong code"
  fi
  rm -f "$tmp/internal/cloud/aws/cited.go"

  # A mention inside a comment or a string literal is not a call.
  cat >"$tmp/internal/cloud/aws/mentions.go" <<'MENTIONS'
package aws

// Handlers must not call context.Background(); they thread cmd.Context().
func mentions() string {
	/* context.TODO() is not allowed here either */
	return "context.Background()"
}
MENTIONS
  if [[ -n "$(scan_tree "$tmp")" ]]; then
    die "a mention in a comment or string literal was reported as a call: $(scan_tree "$tmp")"
  fi
  rm -f "$tmp/internal/cloud/aws/mentions.go"

  if [[ -n "$(scan_tree "$tmp")" ]]; then
    die "tree still flagged after every plant was removed: $(scan_tree "$tmp")"
  fi

  echo "context-awareness self-test passed: gate catches Background() and TODO() under cmd/ and internal/, and stays silent on compliant code and tests."
}

cd "$(dirname "$0")/.."

self_test

offenders="$(scan_tree .)"

if [[ -n "$offenders" ]]; then
  echo "context-awareness check failed: cloud calls must thread cmd.Context(), not a detached context." >&2
  echo "" >&2
  echo "$offenders" >&2
  echo "" >&2
  echo "Derive the context from cmd.Context() so SIGINT/SIGTERM cancels in-flight cloud calls." >&2
  echo "The only allowed detached context is the signal.NotifyContext base in Execute()." >&2
  exit 1
fi

echo "context-awareness check passed: no detached contexts outside tests and the signal bootstrap."
