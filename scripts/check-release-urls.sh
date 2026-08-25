#!/usr/bin/env bash
#
# check-release-urls.sh — assert the README's download URLs name assets
# goreleaser actually produces.
#
# .goreleaser.yaml decides the asset filenames and the README repeats them, so
# without a comparison the two sides only agree by memory. A documented install
# command that 404s is a defect a reader can only find by running it, and the
# README hands the same commands to CI recipes people paste.
#
# The comparison runs offline against the committed config, so the verdict is a
# function of the commit under test: it holds with no release published and no
# network.
#
# Usage: scripts/check-release-urls.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lib_dir="${repo_root}/scripts/lib"
cd "$repo_root"

note() { printf '  %s\n' "$1" >&2; }

# name_template_in extracts the name_template declared in a top-level section of
# a goreleaser config: "archives" or "checksum".
#
# Three things it does deliberately, each of which was a defect:
#
#   COMMENTS ARE STRIPPED FIRST. An unanchored /name_template:/ matches a
#   commented-out one, and a superseded template kept above the live one as a
#   comment is a normal thing to find in a config.
#
#   ALL MATCHES ARE RECONCILED, not the first. First-match-wins means a dead
#   declaration above a live one wins the search, and the gate then compares the
#   README against a template nothing produces. Where a section declares more
#   than one, that is a config this parser cannot read unambiguously and it says
#   so rather than picking.
#
#   THE SECTION IS TRACKED BY INDENTATION, not by "the first name_template in the
#   file". A list item under `archives:` is indented past column 0 and may carry
#   a `- ` prefix; the next top-level key ends the section.
name_template_in() {
  local file="$1" section="$2"
  awk -v style=hash -f "${lib_dir}/strip-comments.awk" "$file" |
    awk -v want="$section" '
      # A top-level key (column 0, not a list item) opens or closes a section.
      /^[A-Za-z_][A-Za-z0-9_-]*:/ {
        key = $0
        sub(/:.*/, "", key)
        insection = (key == want)
        next
      }
      insection && /^[[:space:]]*(-[[:space:]]+)?name_template:[[:space:]]*/ {
        value = $0
        sub(/^[[:space:]]*(-[[:space:]]+)?name_template:[[:space:]]*/, "", value)
        sub(/[[:space:]]+$/, "", value)
        gsub(/^"|"$/, "", value)
        found[++n] = value
      }
      END {
        if (n == 0) exit 3
        if (n > 1) {
          for (i = 1; i <= n; i++) print "AMBIGUOUS: " found[i] > "/dev/stderr"
          exit 4
        }
        print found[1]
      }
    '
}

# compare_urls checks one README against one goreleaser config. Taking both as
# arguments is what lets the self-test drive it with fixtures rather than needing
# a repo whose README is genuinely wrong.
#
# Exit: 0 agree, 1 disagree, 2 nothing was compared (which is not a pass).
compare_urls() {
  local goreleaser="$1" readme="$2"
  local fail=0 checked=0 skipped=0
  local archive_tpl checksum_tpl archive_versioned checksum_versioned url asset

  # ─── what goreleaser will produce ───
  if ! archive_tpl=$(name_template_in "$goreleaser" archives); then
    echo "error: could not read a single archive name_template from $goreleaser" >&2
    return 2
  fi
  if ! checksum_tpl=$(name_template_in "$goreleaser" checksum); then
    echo "error: could not read a single checksum name_template from $goreleaser" >&2
    return 2
  fi

  [ -n "$archive_tpl" ] || { echo "error: empty archive name_template in $goreleaser" >&2; return 2; }
  [ -n "$checksum_tpl" ] || { echo "error: empty checksum name_template in $goreleaser" >&2; return 2; }

  # The only property the URLs depend on: whether the version is part of the
  # filename. If it is, `releases/latest/download/<static-name>` cannot resolve —
  # there is nothing for GitHub to substitute — and every URL must carry an
  # explicit version instead.
  archive_versioned=0
  checksum_versioned=0
  case "$archive_tpl" in *'{{ .Version }}'*|*'{{.Version}}'*) archive_versioned=1 ;; esac
  case "$checksum_tpl" in *'{{ .Version }}'*|*'{{.Version}}'*) checksum_versioned=1 ;; esac

  # ─── what the README claims ───
  local urls
  mapfile -t urls < <(grep -oE 'https://github\.com/nanohype/cloudgov/releases/[^"'"'"' )]*' "$readme" || true)

  if [ "${#urls[@]}" -eq 0 ]; then
    echo "error: $readme documents no release download URLs — did the install section move?" >&2
    return 2
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

    # goreleaser writes .Os / .Arch lowercase, so a title-cased segment names an
    # asset no release carries. It reads as plausible, which is why it is worth
    # naming rather than leaving to the version check above.
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
    return 1
  fi

  # A verdict over nothing is not a pass. Every match being a link to the releases
  # page means no documented download URL was compared against the config, which is
  # the one thing this script exists to do.
  if [ "$checked" -eq 0 ]; then
    echo "error: $skipped release link(s) found, none of them a download URL — nothing was compared." >&2
    echo "       The install section documents no asset this can check against $goreleaser." >&2
    return 2
  fi

  printf 'ok: %s documented download URL(s) agree with %s (%s releases-page link(s) not compared)\n' \
    "$checked" "$goreleaser" "$skipped"
  return 0
}

# ── Why this script self-tests ────────────────────────────────────────────────
#
# This gate's whole value is that it goes red on a wrong URL, and a wrong URL
# produces no other signal until a reader runs the command and gets a 404. A
# comparison that silently matches nothing — a changed repo path, a moved install
# section, a template this parser no longer recognises — reports the same "ok" as
# one that compared every URL and found them right.
#
# So it proves it can reject before it is allowed to report a pass: each defect
# shape is driven against a fixture pair, and a correct pair is required to come
# back clean so the gate is not simply always-red.
self_test_die() {
  echo "check-release-urls self-test FAILED: $*" >&2
  echo "The gate could not be shown to reject, so its pass is not evidence." >&2
  exit 1
}

self_test() {
  local tmp got_tpl
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  cat >"$tmp/goreleaser.yaml" <<'CFG'
archives:
  - name_template: "cloudgov_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
checksum:
  name_template: "cloudgov_{{ .Version }}_checksums.txt"
CFG

  local base=https://github.com/nanohype/cloudgov/releases

  # A README naming versioned, lowercase assets agrees with that config.
  cat >"$tmp/good.md" <<MD
curl -LO $base/download/v2.0.0/cloudgov_2.0.0_darwin_arm64.tar.gz
curl -LO $base/download/v2.0.0/cloudgov_2.0.0_checksums.txt
MD
  compare_urls "$tmp/goreleaser.yaml" "$tmp/good.md" >/dev/null ||
    self_test_die "rejected a README whose URLs match the config"

  # latest/download cannot resolve a versioned filename.
  cat >"$tmp/latest.md" <<MD
curl -LO $base/latest/download/cloudgov_2.0.0_darwin_arm64.tar.gz
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/latest.md" >/dev/null 2>&1 ||
    self_test_die "accepted latest/download against a versioned name_template"

  # A title-cased OS segment names an asset no release carries.
  cat >"$tmp/case.md" <<MD
curl -LO $base/download/v2.0.0/cloudgov_2.0.0_Darwin_arm64.tar.gz
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/case.md" >/dev/null 2>&1 ||
    self_test_die "accepted a title-cased OS segment"

  # An asset with no version segment against a versioned template.
  cat >"$tmp/unversioned.md" <<MD
curl -LO $base/download/v2.0.0/cloudgov_darwin_arm64.tar.gz
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/unversioned.md" >/dev/null 2>&1 ||
    self_test_die "accepted an unversioned asset against a versioned name_template"

  # Nothing to compare is not a pass, in either of its two shapes.
  printf 'no links here\n' >"$tmp/empty.md"
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/empty.md" >/dev/null 2>&1 ||
    self_test_die "reported a pass for a README documenting no download URLs"

  printf 'see %s for downloads\n' "$base" >"$tmp/pageonly.md"
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/pageonly.md" >/dev/null 2>&1 ||
    self_test_die "reported a pass when every link was the releases page"

  # A config this parser cannot read is an error, not an empty expectation.
  printf 'archives: []\n' >"$tmp/nocfg.yaml"
  ! compare_urls "$tmp/nocfg.yaml" "$tmp/good.md" >/dev/null 2>&1 ||
    self_test_die "accepted a goreleaser config declaring no name_template"

  # ── the extractor's own three failure modes ──
  #
  # A commented-out template above the live one. Taking the first match, over a
  # view that includes comments, reads the dead one — and the gate then compares
  # the README against a filename nothing produces.
  #
  # Two shapes, because they break different halves. A commented-out declaration
  # ABOVE the live one is what first-match-wins reads; a trailing comment on the
  # live line is what an unstripped view folds into the value itself.
  cat >"$tmp/commented.yaml" <<'CFG'
archives:
  - name_template: "cloudgov_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
checksum:
  # name_template: "dead_{{ .Version }}_checksums.txt"
  name_template: "cloudgov_{{ .Version }}_checksums.txt"   # was dead_{{ .Version }}
CFG
  got_tpl="$(name_template_in "$tmp/commented.yaml" checksum)"
  case "$got_tpl" in
    "cloudgov_{{ .Version }}_checksums.txt") ;;
    *dead_*) self_test_die "a commented-out template was read into the value: ${got_tpl}" ;;
    *"#"*) self_test_die "a trailing comment was read as part of the template: ${got_tpl}" ;;
    *) self_test_die "could not read the live checksum template past the comments around it: ${got_tpl}" ;;
  esac

  # A list-item template. `archives:` declares a list, so the live template
  # carries a `- ` prefix that a bare column-anchored pattern misses entirely —
  # and the search then falls through to whichever section declares the next one.
  cat >"$tmp/listitem.yaml" <<'CFG'
archives:
  - id: cloudgov
    name_template: "cloudgov_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
checksum:
  name_template: "cloudgov_{{ .Version }}_checksums.txt"
CFG
  case "$(name_template_in "$tmp/listitem.yaml" archives)" in
    *"{{ .Os }}"*) ;;
    *checksums*) self_test_die "read the checksum template as the archive template" ;;
    *) self_test_die "could not read an archive template declared as a list item" ;;
  esac

  # Two live templates in one section is a config this parser cannot read
  # unambiguously. Picking one would be a guess presented as a reading.
  cat >"$tmp/ambiguous.yaml" <<'CFG'
archives:
  - name_template: "one_{{ .Version }}"
  - name_template: "two_{{ .Version }}"
checksum:
  name_template: "cloudgov_{{ .Version }}_checksums.txt"
CFG
  ! name_template_in "$tmp/ambiguous.yaml" archives >/dev/null 2>&1 ||
    self_test_die "picked one of two archive templates instead of reporting the config as unreadable"

  echo "check-release-urls self-test passed: the gate rejects latest/download, OS casing, missing versions, an empty comparison, a commented-out template, and an ambiguous config."
}

self_test
compare_urls .goreleaser.yaml README.md
