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
# The tracked set is the same on both. Where git cannot answer — a scratch tree
# built by a self-test, an exported tarball — it falls back to find, which is the
# right answer there because such a tree holds only what the test put in it.
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

  find "$root" -type f -not -path '*/.git/*' "$@" 2>/dev/null
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
