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

# scan_tree prints one "path:line:content" per offending occurrence under $1, or
# nothing. Both detached-context spellings are matched; _test.go files and the
# single signal.NotifyContext bootstrap are excluded.
#
# The trailing `|| true` on the pipeline is deliberate: grep exits 1 on "no
# matches", which under `set -e` would abort the script on the *success* case.
scan_tree() {
  local root="$1"
  grep -rnE 'context\.(Background|TODO)\(\)' "$root" --include='*.go' 2>/dev/null \
    | grep -v '_test\.go:' \
    | grep -v 'signal\.NotifyContext(context\.Background()' \
    || true
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
