#!/usr/bin/env bash
#
# check-shell-portability.sh — a gate script must run on the oldest bash a
# contributor is likely to have.
#
# The bash on a macOS system path is 3.2. A bash 4 builtin there is not a syntax
# error: it is a command that does not exist, so the script starts, runs under
# `set -e` until it reaches that line, and aborts partway through. A gate that
# aborts partway through has checked some of the tree and reported on none of it.
#
# PARSING CANNOT FIND THIS. `bash -n` accepts every script in this repo including
# one calling a builtin the interpreter does not have, because a missing command
# is a runtime fact. That is why the constructs are enumerated by name rather
# than inferred from a parse, and why the run probe below runs the script.
#
# Scope: bash scripts only. Every script here declares bash, so there is no
# POSIX-sh half to this gate — a `#!/bin/sh` script would need running under
# dash, since a macOS /bin/sh is bash in POSIX mode and accepts bash-isms that
# Debian's dash rejects. The self-test proves the classifier can tell the two
# apart, so adding an sh script fails here rather than passing silently.
#
# Usage: scripts/check-shell-portability.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
lib_dir="${repo_root}/scripts/lib"

# Each entry is "label|extended-regex". Enumerated rather than derived: this is a
# closed list of builtins and expansions bash gained after 3.2, and a rule that
# tried to infer them from a parse would find none of them.
BASH4_CONSTRUCTS=(
  'mapfile|(^|[^[:alnum:]_-])mapfile[[:space:]]'
  'readarray|(^|[^[:alnum:]_-])readarray[[:space:]]'
  'associative array|declare[[:space:]]+-[A-Za-z]*A|local[[:space:]]+-[A-Za-z]*A'
  'case-modifying expansion|\$\{[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?(,,|\^\^)'
)

# declared_shell prints bash, sh, or other for $1, from its shebang.
declared_shell() {
  local first
  first="$(head -1 "$1")"
  case "$first" in
    '#!'*bash*) echo bash ;;
    '#!'*/sh | '#!'*env\ sh) echo sh ;;
    *) echo other ;;
  esac
}

# scan_constructs prints "label:line:text" for each bash-4 construct in $1.
#
# COMMENTS ARE STRIPPED AND STRINGS ARE NOT. The view has to match what bash
# executes: `"${x,,}"` is a case-modifying expansion the shell performs, and it
# lives inside double quotes, so a string-blanked view erases the construct and
# reports the file as portable. The comment view is the other half — `mapfile`
# named in a sentence saying why it is not used is not a use of it, and a gate
# that could not tell them apart would make the explanation unwritable.
#
# Single-quoted bodies are blanked and double-quoted ones are not, which is the
# same distinction bash makes: an expansion in double quotes is performed, and in
# single quotes it is literal text. A fixture written as a single-quoted literal
# — the way this gate's own self-test writes its probes — is therefore not a use.
scan_constructs() {
  local file="$1" entry label pattern stripped
  # Heredocs are blanked FIRST, on the raw file. A heredoc tag is usually
  # quoted — `<<'"'"'FIX'"'"'` — so a string-blanking pass run before this one erases the
  # tag and leaves the body looking like ordinary code.
  if ! stripped="$(awk -f "${lib_dir}/blank-heredocs.awk" "$file" | awk -v style=hash -v strings=blank-single -f "${lib_dir}/strip-comments.awk")"; then
    echo "scan_constructs: the comment stripper failed on ${file}; it was not examined" >&2
    return 1
  fi
  for entry in "${BASH4_CONSTRUCTS[@]}"; do
    label="${entry%%|*}"
    pattern="${entry#*|}"
    printf '%s\n' "$stripped" |
      grep -nE -- "$pattern" |
      sed "s|^|${label}:|" || true
  done
}

self_test_die() {
  echo "check-shell-portability self-test FAILED: $*" >&2
  echo "The gate could not be shown to reject, so its pass is not evidence." >&2
  exit 1
}

# scanned runs scan_constructs and dies with a VERDICT if it cannot run.
#
# Called bare in a substitution, a failure aborts the script through errexit
# before any message is printed, and a gate that exits non-zero saying nothing
# is indistinguishable from one that crashed.
scanned() {
  local out
  out="$(scan_constructs "$1")" ||
    self_test_die "the construct scanner could not run against $1, so nothing here is evidence"
  printf '%s' "$out"
}

self_test() {
  local tmp found clean_found
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # ── the classifier tells a bash script from an sh one ──
  printf '#!/usr/bin/env bash\ntrue\n' >"$tmp/a.sh"
  printf '#!/bin/sh\ntrue\n' >"$tmp/b.sh"
  printf '#!/usr/bin/env python3\n' >"$tmp/c.py"
  [ "$(declared_shell "$tmp/a.sh")" = bash ] || self_test_die "a bash shebang was not classified as bash"
  [ "$(declared_shell "$tmp/b.sh")" = sh ] || self_test_die "a /bin/sh shebang was not classified as sh"
  [ "$(declared_shell "$tmp/c.py")" = other ] || self_test_die "a python shebang was classified as a shell script"

  # ── one violation per fixture, and the detector proven in both directions ──
  #
  # Each construct gets its own file. A fixture carrying two would be rejected
  # for whichever is found first and would prove nothing about the other.
  printf '#!/usr/bin/env bash\nmapfile -t x < /dev/null\n' >"$tmp/m.sh"
  printf '#!/usr/bin/env bash\nreadarray -t x < /dev/null\n' >"$tmp/r.sh"
  printf '#!/usr/bin/env bash\ndeclare -A x\n' >"$tmp/d.sh"
  printf '#!/usr/bin/env bash\ny=ABC\necho "${y,,}"\n' >"$tmp/l.sh"
  # Quoted singly so this list is data to the scanner as well as to the reader:
  # a bare `mapfile` token here is a use of the construct as far as any view of
  # this file's code is concerned, and the gate would reject itself for carrying
  # its own fixtures.
  for probe in 'm:mapfile' 'r:readarray' 'd:associative' 'l:case-modifying'; do
    found="$(scanned "$tmp/${probe%%:*}.sh")"
    printf '%s\n' "$found" | grep -qF "${probe#*:}" ||
      self_test_die "a ${probe#*:} construct was not detected (got: ${found})"
  done

  # A clean bash 4-free script must produce nothing — the same detector, the
  # other direction, so a rule matching everything fails here too.
  printf '#!/usr/bin/env bash\nx=()\nwhile IFS= read -r l; do x+=("$l"); done < /dev/null\necho "${#x[@]}"\n' >"$tmp/clean.sh"
  clean_found="$(scanned "$tmp/clean.sh")"
  [ -z "$clean_found" ] ||
    self_test_die "a portable script was reported as using a bash 4 construct: ${clean_found}"

  # A construct inside a heredoc belongs to the file being written, not to this
  # one — and the line after the delimiter is this file's code again.
  {
    printf '#!/usr/bin/env bash\ncat >/tmp/x <<%s\n' "'FIX'"
    printf 'mapfile -t y < /dev/null\nFIX\ntrue\n'
  } >"$tmp/heredoc.sh"
  [ -z "$(scanned "$tmp/heredoc.sh")" ] ||
    self_test_die "a construct inside a heredoc body was counted as a use by the writing script"
  {
    printf '#!/usr/bin/env bash\ncat >/tmp/x <<%s\n' "'FIX'"
    printf 'harmless\nFIX\nmapfile -t y < /dev/null\n'
  } >"$tmp/afterdoc.sh"
  printf '%s\n' "$(scanned "$tmp/afterdoc.sh")" | grep -q 'mapfile' ||
    self_test_die "the heredoc skip ran past its delimiter and hid real code beneath it"

  # A construct NAMED IN PROSE is not a use of it. Without this the only way to
  # explain the rule is to stop explaining it.
  printf '#!/usr/bin/env bash\n# mapfile is deliberately not used here.\ntrue\n' >"$tmp/prose.sh"
  [ -z "$(scanned "$tmp/prose.sh")" ] ||
    self_test_die "a construct named in a comment was counted as a use of it"

  echo "check-shell-portability self-test passed: it classifies shebangs, detects each bash 4 construct on its own fixture, stays silent on portable code, and does not read a comment as code."
}

self_test

fail=0
checked=0
sh_scripts=0
for script in scripts/*.sh; do
  [ -f "$script" ] || continue
  case "$(declared_shell "$script")" in
    sh)
      sh_scripts=$((sh_scripts + 1))
      echo "::error::${script} declares /bin/sh. This gate does not check POSIX-sh compatibility, and it cannot be checked by running it here: a macOS /bin/sh is bash in POSIX mode and accepts bash-isms Debian's dash rejects. Declare bash, or add a dash run to this gate." >&2
      fail=1
      continue
      ;;
    other) continue ;;
  esac
  checked=$((checked + 1))
  if ! found="$(scan_constructs "$script")"; then
    echo "::error::${script} could not be examined" >&2
    fail=1
    continue
  fi
  if [ -n "$found" ]; then
    echo "::error::${script} uses a bash 4 construct; on a macOS system bash (3.2) it aborts partway through rather than failing to parse:" >&2
    printf '%s\n' "$found" | sed 's/^/    /' >&2
    fail=1
  fi
done

if [ "$checked" -eq 0 ]; then
  echo "error: no bash scripts found in scripts/ — the enumeration is broken, not the tree." >&2
  exit 2
fi

# ─── the run probe, where the world provides one ───
#
# The scan above is what the commit controls and is the gate. Running each script
# under a bash older than 4 is a stronger answer and is available only where such
# a bash exists — a macOS system bash, not a CI runner. Which one happened is
# printed, because "portable" backed by a scan and "portable" backed by a run are
# different claims and must not read alike.
old_bash=""
for candidate in /bin/bash /usr/bin/bash; do
  [ -x "$candidate" ] || continue
  major="$("$candidate" -c 'echo "${BASH_VERSINFO[0]}"' 2>/dev/null || echo 0)"
  if [ "${major:-0}" -gt 0 ] && [ "$major" -lt 4 ]; then
    old_bash="$candidate"
    break
  fi
done

if [ -n "$old_bash" ]; then
  probe_failures=0
  probed=0
  for script in scripts/*.sh; do
    [ "$(declared_shell "$script")" = bash ] || continue
    # Two exclusions, each because RUNNING the script is the wrong thing to do
    # rather than because its portability does not matter.
    #
    #   this file        — running it from inside itself recurses.
    #   coverage.sh      — it runs the Go test suite. Probing whether its first
    #                      lines parse would cost a second full test run under a
    #                      second interpreter, and a gate slow enough to be
    #                      skipped locally is a gate that stops being run.
    #   the floor        — it mutates the working tree and re-runs every other
    #                      gate, so probing it here nests the whole suite inside
    #                      one of its own members and leaves the tree mid-mutation
    #                      if the probe is interrupted.
    #
    # Both are still covered by the construct scan above, which is the gate; what
    # they lose is the stronger run evidence, and this says so rather than
    # counting them among the scripts that were run.
    case "$(basename "$script")" in
      "$(basename "${BASH_SOURCE[0]}")" | check-positive-controls.sh | coverage.sh) continue ;;
    esac
    probed=$((probed + 1))
    out="$("$old_bash" "$script" 2>&1)" || true
    if printf '%s\n' "$out" | grep -qE 'command not found|bad substitution|declare: -A: invalid option'; then
      echo "::error::${script} fails under $("$old_bash" --version | head -1):" >&2
      printf '%s\n' "$out" | grep -E 'command not found|bad substitution|invalid option' | sed 's/^/    /' >&2
      fail=1
      probe_failures=$((probe_failures + 1))
    fi
  done
  printf 'ok: %s bash script(s) carry no bash 4 construct; %s of them were also RUN under %s\n' \
    "$checked" "$probed" "$("$old_bash" --version | head -1 | sed 's/ (.*//')"
else
  printf 'ok: %s bash script(s) carry no bash 4 construct (scanned; no bash older than 4 on this machine to run them under)\n' "$checked"
fi

if [ "$fail" -ne 0 ]; then
  echo "== shell portability NOT met =="
  exit 1
fi
