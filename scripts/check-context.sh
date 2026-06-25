#!/usr/bin/env bash
#
# check-context.sh — enforce that command handlers thread the signal-aware context.
#
# CLAUDE.md: "All cloud API calls must be context-aware." Every cobra RunE handler
# must derive its context from cmd.Context(), which the root command roots in a
# context cancelled on the first SIGINT/SIGTERM. A handler that calls
# context.Background() instead severs that chain, so an interrupt can no longer
# unwind its in-flight cloud calls.
#
# The single legitimate context.Background() in cmd/ is the signal-context
# bootstrap in Execute() (signal.NotifyContext(context.Background(), ...)). Any
# other occurrence under cmd/ fails the check.
#
# Run locally the same way CI does: scripts/check-context.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# All context.Background() occurrences under cmd/, minus the one allowed site:
# the signal.NotifyContext base in Execute(). grep -v drops that line; anything
# left is a handler that bypassed cmd.Context().
offenders="$(grep -rn 'context\.Background()' cmd/ --include='*.go' \
  | grep -v 'signal\.NotifyContext(context\.Background()' || true)"

if [[ -n "$offenders" ]]; then
  echo "context-awareness check failed: cmd/ handlers must use cmd.Context(), not context.Background()." >&2
  echo "" >&2
  echo "$offenders" >&2
  echo "" >&2
  echo "Derive the context from cmd.Context() so SIGINT/SIGTERM cancels in-flight cloud calls." >&2
  echo "The only allowed context.Background() in cmd/ is the signal.NotifyContext base in Execute()." >&2
  exit 1
fi

echo "context-awareness check passed: all cmd/ handlers thread cmd.Context()."
