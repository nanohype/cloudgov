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
# The comparison is against the SET of assets the config will publish — the build
# matrix rendered with `ignore:` and `format_overrides` applied — not against
# properties of the name template. A template-shaped check passes a wrong arch
# token, a wrong extension and a platform pair the matrix excludes, all of which
# are 404s.
#
# It runs offline against the committed config, so the verdict is a function of
# the commit under test: it holds with no release published and no network.
#
# Usage: scripts/check-release-urls.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lib_dir="${repo_root}/scripts/lib"
cd "$repo_root"

note() { printf '  %s\n' "$1" >&2; }

# normalize_asset turns a documented filename into the form the rendered set
# uses: whatever version the URL interpolates becomes the literal VERSION.
#
# A shell variable, a literal tag and a bare semver are all the same claim about
# which file exists; only the version differs, and the config is checked offline
# against no particular tag.
normalize_asset() {
  printf '%s' "$1" |
    sed -E 's/\$\{[A-Za-z_][A-Za-z0-9_]*\}/VERSION/g; s/(^|_)v?[0-9]+\.[0-9]+\.[0-9]+(_|$)/\1VERSION\2/g'
}

# compare_urls checks one README against one goreleaser config. Taking both as
# arguments is what lets the self-test drive it with fixtures rather than needing
# a repo whose README is genuinely wrong.
#
# It compares each documented asset against the SET goreleaser will publish,
# rendered from the build matrix, rather than against properties of the name
# template. Three spot checks — is the version embedded, is there a digit-dot-
# digit, is the OS lowercase — pass a wrong arch token, a wrong extension and a
# platform pair `ignore:` excludes entirely. Only the set answers "will this file
# exist".
#
# Exit: 0 agree, 1 disagree, 2 nothing was compared (which is not a pass).
compare_urls() {
  local goreleaser="$1" readme="$2"
  local fail=0 checked=0 skipped=0
  local url asset normalized rendered

  # ─── what goreleaser will publish ───
  if ! rendered=$(python3 "${lib_dir}/goreleaser-assets.py" "$goreleaser"); then
    echo "error: could not render the asset set from $goreleaser" >&2
    return 2
  fi
  if [ -z "$rendered" ]; then
    echo "error: $goreleaser rendered no assets — there is nothing to compare against." >&2
    return 2
  fi

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
    normalized="$(normalize_asset "$asset")"

    # Every rendered name carries the version, so `latest/download/<name>` has
    # nothing for GitHub to substitute and resolves to nothing.
    case "$url" in
      */releases/latest/download/*)
        case "$normalized" in
          *VERSION*)
            fail=1
            note "$url"
            note "    uses latest/download, but every published asset embeds the version"
            note "    in its filename — this resolves to nothing. Name an explicit version."
            ;;
        esac
        ;;
    esac

    if ! printf '%s\n' "$rendered" | grep -qxF "$normalized"; then
      fail=1
      note "$url"
      note "    names '$asset', which goreleaser does not publish."
      note "    Published assets (version elided):"
      printf '%s\n' "$rendered" | while IFS= read -r name; do note "      $name"; done
    fi
  done

  if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "README release URLs disagree with $goreleaser." >&2
    echo "== release-URL agreement NOT met ==" >&2
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

  printf 'ok: %s documented download URL(s) each equal an asset %s will publish (%s rendered, %s releases-page link(s) not compared)\n' \
    "$checked" "$goreleaser" "$(printf '%s\n' "$rendered" | wc -l | tr -d ' ')" "$skipped"
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
  local tmp got base
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # A real config, matrix and all — the renderer needs one, and a fixture that is
  # only a name_template would exercise a path the gate never takes.
  cat >"$tmp/goreleaser.yaml" <<'CFG'
project_name: cloudgov
builds:
  - id: cloudgov
    binary: cloudgov
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
    ignore:
      - goos: windows
        goarch: arm64
archives:
  - id: cloudgov
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    format_overrides:
      - goos: windows
        formats: [zip]
checksum:
  name_template: "{{ .ProjectName }}_{{ .Version }}_checksums.txt"
CFG

  base=https://github.com/nanohype/cloudgov/releases

  # ── the renderer itself, before anything is compared against it ──
  got="$(python3 "${lib_dir}/goreleaser-assets.py" "$tmp/goreleaser.yaml")" ||
    self_test_die "could not render the asset set from a well-formed config"
  printf '%s\n' "$got" | grep -qxF 'cloudgov_VERSION_darwin_arm64.tar.gz' ||
    self_test_die "the rendered set omits a platform the matrix builds: $got"
  printf '%s\n' "$got" | grep -qxF 'cloudgov_VERSION_windows_amd64.zip' ||
    self_test_die "format_overrides was not applied; windows must be .zip: $got"
  printf '%s\n' "$got" | grep -qxF 'cloudgov_VERSION_checksums.txt' ||
    self_test_die "the checksum name was not rendered: $got"
  if printf '%s\n' "$got" | grep -q 'windows_arm64'; then
    self_test_die "ignore: was not applied; windows/arm64 is excluded from the matrix"
  fi

  # A README naming assets the matrix actually produces.
  cat >"$tmp/good.md" <<MD
curl -LO $base/download/v2.0.0/cloudgov_2.0.0_darwin_arm64.tar.gz
curl -LO $base/download/v\${VERSION}/cloudgov_\${VERSION}_linux_amd64.tar.gz
curl -LO $base/download/v2.0.0/cloudgov_2.0.0_checksums.txt
MD
  compare_urls "$tmp/goreleaser.yaml" "$tmp/good.md" >/dev/null ||
    self_test_die "rejected a README naming assets the matrix produces"

  # ── the four shapes the old property checks let through ──
  #
  # Each of these passed the previous implementation and is a 404.
  cat >"$tmp/wrongarch.md" <<MD
curl -LO $base/download/v\${VERSION}/cloudgov_\${VERSION}_darwin_x86_64.tar.gz
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/wrongarch.md" >/dev/null 2>&1 ||
    self_test_die "accepted an arch token goreleaser does not emit (x86_64 vs amd64)"

  cat >"$tmp/wrongext.md" <<MD
curl -LO $base/download/v\${VERSION}/cloudgov_\${VERSION}_windows_amd64.tar.gz
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/wrongext.md" >/dev/null 2>&1 ||
    self_test_die "accepted .tar.gz for a platform format_overrides publishes as .zip"

  cat >"$tmp/excluded.md" <<MD
curl -LO $base/download/v\${VERSION}/cloudgov_\${VERSION}_windows_arm64.zip
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/excluded.md" >/dev/null 2>&1 ||
    self_test_die "accepted a platform pair ignore: excludes from the matrix"

  cat >"$tmp/wrongproject.md" <<MD
curl -LO $base/download/v\${VERSION}/totally_\${VERSION}_bogus_name.tar.gz
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/wrongproject.md" >/dev/null 2>&1 ||
    self_test_die "accepted an asset name unrelated to the project"

  # ── the shapes the old implementation did catch, kept ──
  cat >"$tmp/latest.md" <<MD
curl -LO $base/latest/download/cloudgov_2.0.0_darwin_arm64.tar.gz
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/latest.md" >/dev/null 2>&1 ||
    self_test_die "accepted latest/download against a versioned filename"

  cat >"$tmp/case.md" <<MD
curl -LO $base/download/v2.0.0/cloudgov_2.0.0_Darwin_arm64.tar.gz
MD
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/case.md" >/dev/null 2>&1 ||
    self_test_die "accepted a title-cased OS segment"

  # ── nothing to compare is not a pass, in either shape ──
  printf 'no links here\n' >"$tmp/empty.md"
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/empty.md" >/dev/null 2>&1 ||
    self_test_die "reported a pass for a README documenting no download URLs"

  printf 'see %s for downloads\n' "$base" >"$tmp/pageonly.md"
  ! compare_urls "$tmp/goreleaser.yaml" "$tmp/pageonly.md" >/dev/null 2>&1 ||
    self_test_die "reported a pass when every link was the releases page"

  # ── a config the renderer cannot use is an error, not an empty expectation ──
  printf 'project_name: cloudgov\narchives: []\n' >"$tmp/nocfg.yaml"
  ! compare_urls "$tmp/nocfg.yaml" "$tmp/good.md" >/dev/null 2>&1 ||
    self_test_die "accepted a config declaring no archives"

  printf 'builds: [{goos: [linux], goarch: [amd64]}]\narchives: [{name_template: "x"}]\nchecksum: {name_template: "y"}\n' >"$tmp/noproject.yaml"
  ! compare_urls "$tmp/noproject.yaml" "$tmp/good.md" >/dev/null 2>&1 ||
    self_test_die "accepted a config with no project_name"

  cat >"$tmp/unsupported.yaml" <<'CFG'
project_name: cloudgov
builds:
  - goos: [linux]
    goarch: [amd64]
archives:
  - name_template: "{{ .ProjectName }}_{{ .Runtime.Goarm }}"
checksum:
  name_template: "{{ .ProjectName }}_checksums.txt"
CFG
  ! compare_urls "$tmp/unsupported.yaml" "$tmp/good.md" >/dev/null 2>&1 ||
    self_test_die "rendered a name_template using a field it does not implement instead of refusing"

  echo "check-release-urls self-test passed: it renders the matrix (ignore:, format_overrides, checksum) and rejects a wrong arch, a wrong extension, an excluded platform, a foreign name, latest/download, OS casing, an empty comparison, and a config it cannot render."
}

self_test
compare_urls .goreleaser.yaml README.md
