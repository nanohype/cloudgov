# shellcheck shell=bash
#
# tracked_files — list the files a gate should examine, under $1 (default ".").
#
# THE TREE IS NOT THE WORKSPACE. A gate that walks the filesystem grades whatever
# CI happened to put beside the checkout: a sibling repository, a vendored
# dependency tree, a downloaded tool, a cache. That passes on a seat, where none
# of those exist, and grades someone else's code in CI — and the tell is a
# denominator that differs between the two.
#
# The tracked set is the same on both, and there is no other mode: a caller that
# needs to enumerate a scratch tree makes that tree a repository. A fallback to
# find would be the walk this exists to replace, reachable whenever git is absent
# or the working directory is not what the caller assumed.
#
# Usage: tracked_files [root] [find-args...]
#   tracked_files . -name '*.go'
tracked_files() {
  local root="${1:-.}"
  shift || true

  if git -C "$root" rev-parse --show-toplevel >/dev/null 2>&1; then
    local top
    top="$(git -C "$root" rev-parse --show-toplevel)"
    # Only when $root IS the repository root. A subdirectory of a checkout would
    # otherwise list the whole repository.
    if [ "$(cd "$root" && pwd -P)" = "$(cd "$top" && pwd -P)" ]; then
      # -z and a null-delimited read, because a tracked path may contain a space.
      git -C "$root" ls-files -z |
        while IFS= read -r -d '' rel; do
          printf '%s/%s\n' "${root%/}" "$rel"
        done |
        filter_find_args "$@"
      return 0
    fi
  fi

  # NO FILESYSTEM FALLBACK. A tree that is not a repository used to fall back to
  # walking it, which is precisely the behaviour scoping to the tracked set was
  # introduced to stop — the same defect behind a new door, and silent. A caller
  # that needs to enumerate a scratch tree makes it a repository; that is two
  # commands, and it means every caller exercises the path CI runs.
  echo "tracked_files: ${root} is not the root of a git working tree, so the tracked set" >&2
  echo "               cannot be determined. It has NOT enumerated anything." >&2
  return 2
}

# filter_find_args applies the subset of find predicates the callers use to a
# list on stdin. Only -name is supported, because only -name is used; anything
# else is an error rather than a silent pass-through, so a caller cannot add a
# predicate that quietly stops filtering.
filter_find_args() {
  local pattern=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -type) shift 2 ;;
      -name)
        pattern="$2"
        shift 2
        ;;
      *)
        echo "tracked_files: unsupported find predicate '$1'; add it here rather than letting it filter nothing" >&2
        return 2
        ;;
    esac
  done
  if [ -z "$pattern" ]; then
    cat
    return 0
  fi
  local path base
  while IFS= read -r path; do
    base="${path##*/}"
    # shellcheck disable=SC2254  # the pattern is a glob by design
    case "$base" in
      $pattern) printf '%s\n' "$path" ;;
    esac
  done
}

# require_tracked_source fails unless $1 can be enumerated from version control.
#
# THE FALLBACK IS SILENT, AND THAT IS ITS OWN DEFECT. tracked_files drops to a
# filesystem walk where git cannot answer, which is right for a scratch tree a
# self-test built — such a tree holds only what the test put in it. It is wrong
# for the repository: there, the walk is exactly what the tracked set replaced,
# so a missing git or an unexpected working directory silently restores the
# behaviour of grading whatever CI placed beside the checkout.
#
# An exemption on one axis is not an exemption on the others. tracked_files may
# legitimately be unable to consult git; it must never be unable to SAY so. A
# gate that enumerates the repository calls this first, so the precondition is
# named rather than inferred from a suspiciously small count.
require_tracked_source() {
  local root="${1:-.}" what="${2:-this gate}"

  if ! command -v git >/dev/null 2>&1; then
    echo "error: git is not on PATH, so ${what} cannot tell a tracked file from one CI placed" >&2
    echo "       beside the checkout. It has NOT examined anything; that is different from" >&2
    echo "       finding nothing." >&2
    return 2
  fi
  if ! git -C "$root" rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "error: ${root} is not inside a git working tree, so ${what} cannot enumerate the" >&2
    echo "       tracked set. It has NOT examined anything." >&2
    return 2
  fi

  local top
  top="$(git -C "$root" rev-parse --show-toplevel)"
  if [ "$(cd "$root" && pwd -P)" != "$(cd "$top" && pwd -P)" ]; then
    echo "error: ${root} is not the root of its working tree (${top}), so the enumeration would" >&2
    echo "       silently fall back to a filesystem walk." >&2
    return 2
  fi

  # A tracked set of zero is not a small repository; it is an enumeration that
  # failed while returning success.
  local n
  n="$(git -C "$root" ls-files | wc -l | tr -d ' ')"
  if [ "${n:-0}" -eq 0 ]; then
    echo "error: git reports no tracked files under ${root}; ${what} would examine nothing and" >&2
    echo "       report it as a clean tree." >&2
    return 2
  fi
}

# require_tools fails unless every named executable is present.
#
# A GATE THAT DIES ON A MISSING TOOL EXITS NON-ZERO, WHICH IS THE SAFE DIRECTION,
# AND BLAMES THE SHELL. "grep: command not found" tells a reader the interpreter
# is unhappy; it does not tell them the gate CHECKED NOTHING, which is a
# different fact from finding nothing and is the one they need.
#
# Asserted UP FRONT and for the whole run rather than at each call site: a tool
# that decides which files a gate examines, or whether a pattern can match at
# all, is upstream of every assertion the gate makes. Discovering it missing
# halfway through means the earlier assertions were made by a process that could
# not have failed them.
require_tools() {
  local missing=() t
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if [ "${#missing[@]}" -ne 0 ]; then
    echo "error: not on PATH: ${missing[*]}" >&2
    echo "       This gate has NOT examined anything, which is different from finding nothing." >&2
    return 2
  fi
}
