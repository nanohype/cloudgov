"""Report which pin lines renovate.json's customManagers actually cover.

The gate must not carry its own copy of the rule. A restated rule is a second
source of truth: deleting or breaking a customManager would leave the gate
asserting coverage that no longer exists, reporting every pin as watched at the
exact moment nothing watches them.

An earlier version of this script claimed to derive the rule and did not. It
substring-tested each matchString for "renovate:" and then printed a module
constant, so a customManager whose regex matched nothing anywhere in the tree
still produced a full "everything is covered" answer. That is the failure the
indirection exists to prevent, wearing the indirection as cover.

So this applies the configured regexes. Each matchString is compiled and run
against the watched files, and the line carrying the matched `currentValue` is
what gets reported as covered. A manager that matches nothing is an error, not an
empty answer.

The files are read RAW. Renovate reads whole files with comments intact — a
comment IS where these annotations live — so asking "would Renovate match here"
against a comment-stripped view would declare a live manager dead. The view has
to be the consumer's view, not the gate's convenience.

Usage: renovate-annotation.py <renovate.json> <file> [<file> ...]

Prints one "path:line" per covered pin. Exits 2 with a reason on stderr when the
config cannot support the gate.
"""

import json
import re
import sys

# The keys Renovate defines for a regex customManager. Anything else is a key it
# ignores — see the allowlist check below for why that is worse than a missing
# required key rather than milder.
REGEX_MANAGER_KEYS = {
    "customType",
    "description",
    "managerFilePatterns",
    "fileMatch",
    "matchStrings",
    "matchStringsStrategy",
    "depNameTemplate",
    "packageNameTemplate",
    "datasourceTemplate",
    "versioningTemplate",
    "currentValueTemplate",
    "depTypeTemplate",
    "extractVersionTemplate",
    "registryUrlTemplate",
    "autoReplaceStringTemplate",
}

# Renovate writes named groups as (?<name>...); Python spells them (?P<name>...).
NAMED_GROUP = re.compile(r"\(\?<(?![=!])")


def to_python_regex(pattern: str) -> str:
    return NAMED_GROUP.sub("(?P<", pattern)


def covered_lines(pattern: str, path: str, text: str) -> list[tuple[str, int]]:
    """Lines this matchString covers in one file.

    A match spans several lines — the annotation and the pin beneath it — and the
    line that matters is the one carrying `currentValue`, because that is the pin
    Renovate would rewrite. Reporting the whole span would let one annotation
    vouch for every line under it, which is the over-reach this gate exists to
    catch one level up.
    """
    out = []
    named = pattern.groupindex
    for match in pattern.finditer(text):
        # A matchString without a currentValue group is not one Renovate would
        # bump, but it still tells us where the manager looked. Falling back to
        # the match start is the conservative reading: it covers the line the
        # rule actually matched and no more.
        start = match.start("currentValue") if "currentValue" in named else match.start()
        out.append((path, text.count("\n", 0, start) + 1))
    return out


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write("usage: renovate-annotation.py <renovate.json> <file> [<file> ...]\n")
        return 2

    config_path, watched = sys.argv[1], sys.argv[2:]

    try:
        with open(config_path) as handle:
            config = json.load(handle)
    except (OSError, json.JSONDecodeError) as err:
        sys.stderr.write(f"cannot read {config_path}: {err}\n")
        return 2

    # ─── the config's own shape, before anything is derived from it ───
    #
    # This gate READS renovate.json, so a malformed one is not merely a Renovate
    # problem: a manager Renovate would discard still looks like coverage here,
    # and a pin reads as watched by a rule that never runs. The file had no
    # validation of any kind before this.
    #
    # THE COVERAGE IS PARTIAL, deliberately. This checks the shape this gate
    # depends on: the keys are present, the types are right, the regexes compile,
    # and each manager matches something real. It does NOT check the file against
    # Renovate's published schema, and it cannot tell whether a `datasource`
    # names a datasource Renovate implements — a customManager declaring
    # datasource=nonesuch passes here and silently watches nothing in production.
    # Closing that needs the schema vendored or the network, and a validator that
    # claimed to do it without either would be the defect this gate exists to
    # catch.
    if not isinstance(config, dict):
        sys.stderr.write(f"{config_path} is not a JSON object\n")
        return 2
    for key, want in (("customManagers", list), ("extends", list)):
        if key in config and not isinstance(config[key], want):
            sys.stderr.write(f"{config_path}: {key} must be a {want.__name__}\n")
            return 2

    managers = config.get("customManagers") or []
    if not managers:
        sys.stderr.write(
            "renovate.json declares no customManagers. Versions pinned as a value —\n"
            "a tool version passed to an action, a `go install ...@vX` argument — are\n"
            "read by no standard manager, so nothing would watch them.\n"
        )
        return 2

    sources = {}
    for path in watched:
        try:
            with open(path) as handle:
                sources[path] = handle.read()
        except OSError as err:
            sys.stderr.write(f"cannot read watched file {path}: {err}\n")
            return 2
    if not sources:
        sys.stderr.write("no watched files given; there is nothing to report coverage over\n")
        return 2

    covered: set[tuple[str, int]] = set()
    total_match_strings = 0

    for index, manager in enumerate(managers):
        if not isinstance(manager, dict):
            sys.stderr.write(f"customManagers[{index}] is not an object\n")
            return 2
        # Renovate ignores a customManager with no customType and, for the regex
        # type, one with no file patterns — either way it watches nothing while
        # reading as a live rule here.
        if manager.get("customType") != "regex":
            sys.stderr.write(
                f"customManagers[{index}] declares customType "
                f"{manager.get('customType')!r}; this gate only interprets regex managers\n")
            return 2
        if not (manager.get("managerFilePatterns") or manager.get("fileMatch")):
            sys.stderr.write(
                f"customManagers[{index}] declares no managerFilePatterns, so Renovate applies it "
                f"to no file — it watches nothing while reading as a live rule\n")
            return 2

        # An UNKNOWN key is the silent-on-both-sides case, and it is the one a
        # required-key check cannot reach. `datasourceTemplat` for
        # `datasourceTemplate` leaves the manager well-formed enough to match:
        # Renovate drops the template and resolves no datasource, while a gate
        # counting matches sees full coverage. Neither side reports anything.
        #
        # So the keys are an allowlist rather than a required set. A key Renovate
        # does not define is a key it ignores, and a key it ignores is a
        # behaviour the author intended and did not get.
        unknown = sorted(set(manager) - REGEX_MANAGER_KEYS)
        if unknown:
            sys.stderr.write(
                f"customManagers[{index}] declares key(s) Renovate does not define for a regex\n"
                f"manager: {', '.join(unknown)}. Renovate ignores them, so the behaviour they were\n"
                f"meant to configure is silently absent.\n")
            return 2

        patterns = manager.get("matchStrings") or []
        if not patterns:
            sys.stderr.write(f"customManagers[{index}] declares no matchStrings\n")
            return 2

        for raw in patterns:
            total_match_strings += 1
            try:
                compiled = re.compile(to_python_regex(raw), re.MULTILINE)
            except re.error as err:
                sys.stderr.write(f"customManagers[{index}] matchString does not compile: {err}\n  {raw}\n")
                return 2

            hits: list[tuple[str, int]] = []
            for path, text in sources.items():
                hits.extend(covered_lines(compiled, path, text))

            # A rule that matches nothing is dead: it reports the same as a rule
            # that applies everywhere, and it stops applying without any edit
            # saying so.
            if not hits:
                sys.stderr.write(
                    f"customManagers[{index}] matches nothing in the watched files, so it\n"
                    f"watches no pin. Either it has stopped applying or the pins it covered\n"
                    f"are gone:\n  {raw}\n"
                )
                return 2
            covered.update(hits)

    if total_match_strings == 0:
        sys.stderr.write("renovate.json declares customManagers but none with a matchString\n")
        return 2

    for path, line in sorted(covered):
        print(f"{path}:{line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
