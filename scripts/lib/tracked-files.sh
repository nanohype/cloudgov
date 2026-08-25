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
