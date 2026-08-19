#!/usr/bin/env bash
#
# check-release-urls.sh — assert the README's download URLs name assets
# goreleaser actually produces.
#
# The README shipped `cloudgov_Darwin_arm64.tar.gz` and `checksums.txt` against
# a release carrying `cloudgov_2.0.0_darwin_arm64.tar.gz` and
# `cloudgov_2.0.0_checksums.txt` — wrong in the case of the OS segment AND
# missing the version segment entirely. Every documented install command 404'd,
# in the README and in the three CI recipes it hands people to paste.
#
# Nothing caught it because the two sides never met: .goreleaser.yaml decides
# the names, the README repeats them from memory, and no job compares the two.
# This is that comparison. It runs offline against the committed config, so it
# holds without a release existing and without network.
#
# Usage: scripts/check-release-urls.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

fail=0
checked=0
skipped=0
note() { printf '  %s\n' "$1" >&2; }

# ─── what goreleaser will produce ───
archive_tpl=$(grep -E '^\s*name_template:' .goreleaser.yaml | head -1 | sed 's/.*name_template: *//; s/^"//; s/"$//')
checksum_tpl=$(awk '/^checksum:/{f=1} f && /name_template:/{print; exit}' .goreleaser.yaml |
  sed 's/.*name_template: *//; s/^"//; s/"$//')

[ -n "$archive_tpl" ] || { echo "error: no archive name_template in .goreleaser.yaml" >&2; exit 2; }
[ -n "$checksum_tpl" ] || { echo "error: no checksum name_template in .goreleaser.yaml" >&2; exit 2; }

# The only property the URLs depend on: whether the version is part of the
# filename. If it is, `releases/latest/download/<static-name>` cannot resolve —
# there is nothing for GitHub to substitute — and every URL must carry an
# explicit version instead.
archive_versioned=0
checksum_versioned=0
case "$archive_tpl" in *'{{ .Version }}'*|*'{{.Version}}'*) archive_versioned=1 ;; esac
case "$checksum_tpl" in *'{{ .Version }}'*|*'{{.Version}}'*) checksum_versioned=1 ;; esac

# ─── what the README claims ───
# Any release download URL, however it was built.
mapfile -t urls < <(grep -oE 'https://github\.com/nanohype/cloudgov/releases/[^"'"'"' )]*' README.md || true)

if [ "${#urls[@]}" -eq 0 ]; then
  echo "error: README documents no release download URLs — did the install section move?" >&2
  exit 2
fi

for url in "${urls[@]}"; do
  # The bare releases page is a link for humans, not a download. Skips are
  # counted: the guard above rejects an empty match set, but it runs before this
  # filter, so a README linking only to the releases page leaves a non-empty list
  # that this loop then skips in full. Reporting the matched count would then
  # claim agreement for URLs nothing compared.
  case "$url" in
    */releases|*/releases/) skipped=$((skipped + 1)); continue ;;
  esac

  checked=$((checked + 1))
  asset=${url##*/}

  if [ "$archive_versioned" -eq 1 ] || [ "$checksum_versioned" -eq 1 ]; then
    case "$url" in
      */releases/latest/download/*)
        fail=1
        note "$url"
        note "    uses latest/download, but goreleaser embeds the version in the filename"
        note "    ($archive_tpl) — this resolves to nothing. Name an explicit version."
        ;;
    esac
    # A versioned template means the asset name must interpolate a version.
    case "$asset" in
      *'${CLOUDGOV_VERSION}'*|*'${VERSION}'*|*[0-9].[0-9]*) ;;
      *)
        fail=1
        note "$url"
        note "    asset '$asset' carries no version, but goreleaser names archives"
        note "    '$archive_tpl'."
        ;;
    esac
  fi

  # goreleaser writes .Os / .Arch lowercase. `Darwin_arm64` was the original
  # defect and reads as plausible, so it is worth naming rather than leaving to
  # the version check above.
  case "$asset" in
    *Darwin*|*Linux*|*Windows*)
      fail=1
      note "$url"
      note "    '$asset' title-cases the OS; goreleaser emits darwin/linux/windows."
      ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "README release URLs disagree with .goreleaser.yaml." >&2
  exit 1
fi

# A verdict over nothing is not a pass. Every match being a link to the releases
# page means no documented download URL was compared against the config, which is
# the one thing this script exists to do.
if [ "$checked" -eq 0 ]; then
  echo "error: $skipped release link(s) found, none of them a download URL — nothing was compared." >&2
  echo "       The install section documents no asset this can check against .goreleaser.yaml." >&2
  exit 2
fi

printf 'ok: %s documented download URL(s) agree with .goreleaser.yaml (%s releases-page link(s) not compared)\n' \
  "$checked" "$skipped"
