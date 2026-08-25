#!/usr/bin/env bash
# shellcheck disable=SC2016  # single-quoted $ here belongs to awk and printf, not the shell
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

# THREE PARALLEL ARRAYS, indexed together: label, pattern, fixture.
#
# Not one packed string per entry. A separator inside a field takes such a string
# apart, and two of these fields legitimately contain the characters a separator
# would use — the rule for `|&` is one of them. The arrays are checked for equal
# length below, because a table whose columns drift is a rule paired with the
# wrong fixture and it fails silently.
#
# DERIVED PER FEATURE, NOT PER SPELLING. An earlier form of this list named
# `${x^^}` and not `${x^}`, `declare -A` and not -n, -l or -u. Every miss was an
# adjacent spelling of an absence already known about, and the gate passed its
# positive control throughout: a control proves detection of the case it plants,
# never coverage of the class it names. Each rule now matches the FEATURE — the
# option letter, the expansion operator, the redirection form — not one way of
# writing it.
#
# The fixture is what keeps the list honest. The self-test runs every one under a
# bash older than 4 and requires it to FAIL there, so an entry stays only while
# the thing it describes is genuinely absent from bash 3.2. An entry that stops
# being bash-4-only fails the gate rather than quietly widening it.
BASH4_LABELS=(
  'mapfile/readarray builtin'
  'declare/local/typeset -A (associative array)'
  'declare/local/typeset -n (nameref)'
  'declare/local/typeset -l or -u (case attribute)'
  'case-modifying or transform expansion'
  'negative array subscript'
  'printf -v into an array element'
  'wait -n'
  'read -N'
  'pipe stdout and stderr together'
  'named file descriptor redirection'
  'shopt globstar'
  'coproc'
  'fall-through case clause'
  'variable-set test'
)

BASH4_PATTERNS=(
  '(^|[^[:alnum:]_-])(mapfile|readarray)([[:space:]]|$)'
  '(declare|local|typeset)[[:space:]]+-[[:alpha:]]*A'
  '(declare|local|typeset)[[:space:]]+-[[:alpha:]]*n'
  '(declare|local|typeset)[[:space:]]+-[[:alpha:]]*[lu]'
  '[$]\{[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?(\^|,|@[A-Za-z])'
  '[$]\{[A-Za-z_][A-Za-z0-9_]*\[[[:space:]]*-[0-9]'
  'printf[[:space:]]+-v[[:space:]]+["'"'"']?[A-Za-z_][A-Za-z0-9_]*\['
  '(^|[^[:alnum:]_-])wait[[:space:]]+-[[:alpha:]]*n'
  '(^|[^[:alnum:]_-])read[[:space:]]+-[[:alpha:]]*N'
  '[|]&'
  '\{[A-Za-z_][A-Za-z0-9_]*\}[<>]'
  'shopt[[:space:]]+-[su][[:space:]]+globstar'
  '(^|[^[:alnum:]_-])coproc([[:space:]]|$)'
  ';;&'
  '\[\[[^]]*-v[[:space:]]'
)

BASH4_FIXTURES=(
  'mapfile -t zz < /dev/null'
  'declare -A zz; zz[k]=v'
  'zzv=1; declare -n zzr=zzv'
  'declare -l zz=ABC'
  'zz=ab; echo "${zz^}"'
  'zz=(1 2); echo "${zz[-1]}"'
  'zz=(x); printf -v "zz[0]" "%s" hi'
  'true & wait -n'
  'read -N1 zz < /dev/null'
  'echo hi |& cat'
  'exec {zzfd}>/dev/null'
  'shopt -s globstar'
  'coproc ZZ { cat; }'
  'case x in x) : ;;& *) : ;; esac'
  'zz=1; [[ -v zz ]]'
)

# A table whose columns have drifted pairs each rule with someone else's fixture,
# and every assertion below still passes while testing the wrong thing.
if [ "${#BASH4_LABELS[@]}" -ne "${#BASH4_PATTERNS[@]}" ] ||
  [ "${#BASH4_LABELS[@]}" -ne "${#BASH4_FIXTURES[@]}" ]; then
  echo "error: the construct table has ${#BASH4_LABELS[@]} label(s), ${#BASH4_PATTERNS[@]} pattern(s) and ${#BASH4_FIXTURES[@]} fixture(s); its columns have drifted apart" >&2
  exit 2
fi

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
  local file="$1" i label pattern stripped
  # Heredocs are blanked FIRST, on the raw file. A heredoc tag is usually
  # quoted — `<<'"'"'FIX'"'"'` — so a string-blanking pass run before this one erases the
  # tag and leaves the body looking like ordinary code.
  if ! stripped="$(awk -f "${lib_dir}/blank-heredocs.awk" "$file" | awk -v style=hash -v strings=blank-single -f "${lib_dir}/strip-comments.awk")"; then
    echo "scan_constructs: the comment stripper failed on ${file}; it was not examined" >&2
    return 1
  fi
  for i in "${!BASH4_PATTERNS[@]}"; do
    label="${BASH4_LABELS[$i]}"
    pattern="${BASH4_PATTERNS[$i]}"
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

  # ── every entry, both directions, one fixture each ──
  #
  # Each construct gets its own file. A fixture carrying two would be rejected
  # for whichever is found first and would prove nothing about the other.
  #
  # Two assertions per entry, and the second is what makes the list a class
  # rather than a habit:
  #
  #   the scanner DETECTS it        — the rule matches the feature it names
  #   an old bash REJECTS it        — the feature really is absent from bash 3.2
  #
  # Without the second, an entry can describe something bash 3.2 supports
  # perfectly well and nobody finds out. Without the first, the entry is prose.
  local i label fixture probe_file detected old_probe old_rc verified=0
  for i in "${!BASH4_PATTERNS[@]}"; do
    label="${BASH4_LABELS[$i]}"
    fixture="${BASH4_FIXTURES[$i]}"
    probe_file="$tmp/construct.sh"
    printf '#!/usr/bin/env bash\nset -euo pipefail\n%s\n' "$fixture" >"$probe_file"

    detected="$(scanned "$probe_file")"
    [ -n "$detected" ] ||
      self_test_die "the rule for '${label}' does not match its own fixture: ${fixture}"

    if [ -n "${SELF_TEST_OLD_BASH:-}" ]; then
      old_rc=0
      old_probe="$("$SELF_TEST_OLD_BASH" "$probe_file" 2>&1)" || old_rc=$?
      # The captured output is reported, not discarded. When this assertion
      # fires, what the old shell actually said is the whole diagnosis — an entry
      # that ran clean and one that failed for an unrelated reason look identical
      # from the status alone.
      [ "$old_rc" -ne 0 ] ||
        self_test_die "'${label}' is listed as unavailable before bash 4, and $("$SELF_TEST_OLD_BASH" --version | head -1 | sed 's/ (.*//') ran its fixture without error (output: ${old_probe:-<none>}); the entry describes an absence that is not there"
      verified=$((verified + 1))
    fi
  done
  rm -f "$tmp/construct.sh"

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

  # The denominator, and which of the two answers this machine gave. A table
  # verified by execution and one merely asserted are different claims, and a
  # single "passed" line for both hides the machine that could have checked.
  if [ -n "${SELF_TEST_OLD_BASH:-}" ]; then
    printf 'check-shell-portability self-test passed: %s construct(s) each detected by its own rule and each CONFIRMED absent by running it under %s; shebangs classified; portable code, comments and heredoc bodies left alone.\n' \
      "$verified" "$("$SELF_TEST_OLD_BASH" --version | head -1 | sed 's/ (.*//')"
  else
    printf 'check-shell-portability self-test passed: %s construct(s) each detected by its own rule; shebangs classified; portable code, comments and heredoc bodies left alone. No bash older than 4 on this machine, so the table was NOT confirmed by execution.\n' \
      "${#BASH4_PATTERNS[@]}"
  fi
}

# ─── the old interpreter, found before anything depends on it ───
#
# Both the self-test and the run probe need it, and the self-test needs it FIRST:
# it uses it to confirm that every construct in the table really is absent from a
# bash older than 4. Discovering it after the self-test would leave that half of
# the table unverified on the one machine able to verify it.
old_bash=""
for candidate in /bin/bash /usr/bin/bash; do
  [ -x "$candidate" ] || continue
  major="$("$candidate" -c 'echo "${BASH_VERSINFO[0]}"' 2>/dev/null || echo 0)"
  if [ "${major:-0}" -gt 0 ] && [ "$major" -lt 4 ]; then
    old_bash="$candidate"
    break
  fi
done

# The self-test reads this to decide whether it can verify the table by
# execution. Empty is not a failure — it is a machine with no old bash — and the
# gate says which of the two happened rather than reporting the same line for
# both.
SELF_TEST_OLD_BASH="$old_bash"

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
