"""Render the exact set of asset filenames a goreleaser config will publish.

check-release-urls.sh used to compare a documented URL against three properties
of the template — whether the version was embedded, whether a digit-dot-digit
appeared somewhere, and whether the OS segment was title-cased — and print the
word "agree". That is not a comparison against the config; it is three spot
checks that a wrong filename usually passes. Measured against the real config, a
README naming `cloudgov_${VERSION}_darwin_x86_64.tar.gz` (goreleaser emits
amd64), `cloudgov_${VERSION}_windows_amd64.tar.gz` (format_overrides makes that
one .zip) and `cloudgov_${VERSION}_windows_arm64.zip` (ignore: excludes the pair
entirely) all passed. Every one is a 404 a reader can only discover by running
the command.

So this enumerates instead. The build matrix is goos x goarch minus `ignore:`,
the extension comes from `format_overrides` where one applies, and the name comes
from the archive `name_template`. What comes out is the set of things that will
exist — the only thing a documented URL can usefully be compared against.

Version is left as the literal token VERSION rather than resolved, because the
config is checked offline against no particular tag; the caller normalizes the
shell variable in a documented URL to the same token.

Usage: goreleaser-assets.py <.goreleaser.yaml>

Prints one asset filename per line. Exits 2 with a reason on stderr when the
config cannot be rendered.
"""

import sys

try:
    import yaml
except ImportError:  # pragma: no cover - reported, never guessed at
    sys.stderr.write(
        "PyYAML is required to render the goreleaser asset set. Without it this\n"
        "gate cannot compare a documented URL against anything, and a gate that\n"
        "cannot compare must not report agreement.\n"
    )
    raise SystemExit(2)

VERSION_TOKEN = "VERSION"

# The template fields this renderer understands. A template using anything else
# is refused rather than rendered wrongly — a name built from a field this does
# not implement would be compared against, and disagree with, reality.
SUPPORTED = {"ProjectName", "Version", "Os", "Arch", "Tag", "Binary"}


def render(template: str, values: dict) -> str:
    out = template
    for key, value in values.items():
        for spelling in ("{{ ." + key + " }}", "{{." + key + "}}"):
            out = out.replace(spelling, str(value))
    return out


def unresolved(name: str) -> bool:
    return "{{" in name


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: goreleaser-assets.py <.goreleaser.yaml>\n")
        return 2

    try:
        with open(sys.argv[1]) as handle:
            config = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as err:
        sys.stderr.write(f"cannot read {sys.argv[1]}: {err}\n")
        return 2

    project = config.get("project_name") or ""
    if not project:
        sys.stderr.write("no project_name in the config; every asset name starts with it\n")
        return 2

    builds = config.get("builds") or []
    if not builds:
        sys.stderr.write("no builds declared; there is no matrix to render\n")
        return 2

    archives = config.get("archives") or []
    if not archives:
        sys.stderr.write("no archives declared; nothing would be published to document\n")
        return 2

    names = []

    for archive in archives:
        template = archive.get("name_template")
        if not template:
            sys.stderr.write("an archive declares no name_template\n")
            return 2

        # format_overrides: goos -> extension.
        overrides = {}
        for override in archive.get("format_overrides") or []:
            goos = override.get("goos")
            formats = override.get("formats") or ([override["format"]] if "format" in override else [])
            if goos and formats:
                overrides[goos] = formats[0]

        default_formats = archive.get("formats") or ([archive["format"]] if "format" in archive else ["tar.gz"])
        default_ext = default_formats[0]

        for build in builds:
            goos_list = build.get("goos") or []
            goarch_list = build.get("goarch") or []
            if not goos_list or not goarch_list:
                sys.stderr.write("a build declares no goos/goarch; the matrix cannot be rendered\n")
                return 2

            ignored = {
                (entry.get("goos"), entry.get("goarch"))
                for entry in build.get("ignore") or []
            }

            for goos in goos_list:
                for goarch in goarch_list:
                    if (goos, goarch) in ignored:
                        continue
                    name = render(template, {
                        "ProjectName": project,
                        "Version": VERSION_TOKEN,
                        "Tag": "v" + VERSION_TOKEN,
                        "Binary": build.get("binary") or project,
                        "Os": goos,
                        "Arch": goarch,
                    })
                    if unresolved(name):
                        sys.stderr.write(
                            "the archive name_template uses a field this renderer does not\n"
                            f"implement, so the rendered set would be wrong: {name}\n"
                            f"Supported: {', '.join(sorted(SUPPORTED))}\n"
                        )
                        return 2
                    ext = overrides.get(goos, default_ext)
                    names.append(f"{name}.{ext}")

    checksum = (config.get("checksum") or {}).get("name_template")
    if not checksum:
        sys.stderr.write("no checksum name_template; the documented checksums URL cannot be checked\n")
        return 2
    checksum_name = render(checksum, {
        "ProjectName": project,
        "Version": VERSION_TOKEN,
        "Tag": "v" + VERSION_TOKEN,
    })
    if unresolved(checksum_name):
        sys.stderr.write(f"the checksum name_template uses an unsupported field: {checksum_name}\n")
        return 2
    names.append(checksum_name)

    if not names:
        sys.stderr.write("the matrix rendered no assets; there is nothing to compare against\n")
        return 2

    for name in sorted(set(names)):
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
