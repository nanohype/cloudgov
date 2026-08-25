# workflow-run-steps.awk — print only what a workflow EXECUTES.
#
# "Does CI run this gate?" is a question about run: steps. Answering it by
# searching the whole file counts a step name, an env value, an echo, and a
# sentence in a comment — every mention except the one that matters. A gate can
# then be named all over a workflow and executed by none of it.
#
# A step carrying `if: false` is skipped for the same reason: it is present and
# it does not run.
#
# Output is one line per line of run: content, prefixed with its source line
# number so a caller can cite it.
#
# Usage: awk -f workflow-run-steps.awk <workflow.yml>

function flush() {
  if (!skip) for (k = 1; k <= n; k++) print num[k] ":" buf[k]
  n = 0
  skip = 0
}

# A new step at any indent ends the previous one. The dash is then removed so the
# rest of this program sees one shape: `- run: cmd` and a `run:` on its own line
# are the same step, and a rule anchored on `run:` alone matches only the second.
/^[[:space:]]*-[[:space:]]/ {
  flush()
  inrun = 0
  # awk sub() has no capture backreferences, so the dash is replaced in place
  # rather than rebuilt from groups. This rule has already matched leading space
  # then a dash, so the first dash on the line is the step marker.
  sub(/-/, " ")
}

/^[[:space:]]*if:[[:space:]]*false[[:space:]]*$/ { skip = 1 }

# `run: |`, `run: >`, or an inline `run: cmd`.
/^[[:space:]]*run:[[:space:]]*[|>]?[[:space:]]*$/ {
  inrun = 1
  run_indent = match($0, /[^[:space:]]/)
  next
}
/^[[:space:]]*run:[[:space:]]*[^|>[:space:]]/ {
  line = $0
  sub(/^[[:space:]]*run:[[:space:]]*/, "", line)
  n++
  num[n] = FNR
  buf[n] = line
  inrun = 0
  next
}

inrun {
  if ($0 ~ /^[[:space:]]*$/) { n++; num[n] = FNR; buf[n] = ""; next }
  # A block scalar ends at the first line indented no further than its key.
  if (match($0, /[^[:space:]]/) <= run_indent) { inrun = 0 }
  else { n++; num[n] = FNR; buf[n] = $0; next }
}

END { flush() }
