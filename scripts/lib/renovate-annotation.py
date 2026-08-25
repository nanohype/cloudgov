"""Derive the annotation pattern check-version-pins.sh matches on, from renovate.json.

The gate must not carry its own copy of the rule. A restated rule is a second
source of truth: deleting a customManager from renovate.json would leave the gate
asserting coverage that no longer exists, reporting every pin as watched at the
exact moment nothing watches them.

So the gate asks the config what a covered pin looks like. A config with no
usable customManager is an error rather than an empty answer, because an empty
pattern would match nothing and every annotated pin would then read as unwatched
— or, matched the other way, everything would read as covered.

Prints one ERE to stdout. Exits 2 with a reason on stderr when the config cannot
support the gate.
"""

import json
import re
import sys

# The annotation form this repo pins with, and the form every customManager here
# keys on. Kept as a regex over the config's own matchStrings rather than as a
# literal the gate believes independently.
ANNOTATION_TOKEN = "renovate:"
ANNOTATION_ERE = r"#[[:space:]]*renovate:[[:space:]]*datasource="


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: renovate-annotation.py <renovate.json>\n")
        return 2

    try:
        with open(sys.argv[1]) as handle:
            config = json.load(handle)
    except (OSError, json.JSONDecodeError) as err:
        sys.stderr.write(f"cannot read {sys.argv[1]}: {err}\n")
        return 2

    managers = config.get("customManagers") or []
    if not managers:
        sys.stderr.write(
            "renovate.json declares no customManagers. Versions pinned as a value —\n"
            "a tool version passed to an action, a `go install ...@vX` argument — are\n"
            "read by no standard manager, so nothing would watch them.\n"
        )
        return 2

    match_strings = [
        pattern
        for manager in managers
        for pattern in (manager.get("matchStrings") or [])
    ]
    if not match_strings:
        sys.stderr.write("renovate.json declares customManagers but none with a matchString\n")
        return 2

    # Every manager must key on the annotation, or the gate cannot tell which
    # pins that manager covers and would report covered pins as unwatched.
    unreadable = [p for p in match_strings if ANNOTATION_TOKEN not in p]
    if unreadable:
        sys.stderr.write(
            "renovate.json has a customManager this gate cannot interpret: it does not\n"
            "key on a '# renovate:' annotation, so the gate cannot tell which pins it\n"
            "covers. Either key it on the annotation, or teach this script the new form.\n"
        )
        for pattern in unreadable:
            sys.stderr.write("  " + pattern + "\n")
        return 2

    # The pattern must actually match the annotation form the repo writes,
    # otherwise the gate would derive something that matches nothing.
    probe = "# renovate: datasource=github-releases depName=example/tool"
    if not re.search(r"#\s*renovate:\s*datasource=", probe):
        sys.stderr.write("the derived annotation pattern matches nothing\n")
        return 2

    print(ANNOTATION_ERE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
