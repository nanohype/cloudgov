package cmd

import (
	"fmt"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// acceptedSeverities is the whole vocabulary, most severe first. The order is
// the one every help string renders, so a reader meets the levels ranked rather
// than alphabetical.
var acceptedSeverities = []cloud.Severity{
	cloud.SeverityCritical,
	cloud.SeverityHigh,
	cloud.SeverityMedium,
	cloud.SeverityLow,
	cloud.SeverityInfo,
}

// severityUsage renders the help text for a severity flag from the vocabulary it
// validates against, so a flag cannot advertise a level the tool refuses.
func severityUsage(what string) string {
	names := make([]string, 0, len(acceptedSeverities))
	for _, s := range acceptedSeverities {
		names = append(names, string(s))
	}
	return what + ": " + strings.Join(names, ", ")
}

// resolveSeverity converts a caller-supplied severity into a level, or refuses
// it.
//
// Refusing matters because an unrecognised level does not fail — it ranks below
// every real one (cloud.SeverityRank returns 0 by default), and the direction
// that takes the run depends on which side of the comparison it lands:
//
//   - as a REPORTING floor, a typo silently widens the request. Asking for
//     HIGH-and-above with `--severity HIHG` returns every finding at every
//     level, and a caller cannot tell that from the account genuinely being that
//     bad.
//   - as a GATE threshold, a typo silently narrows it to nothing. `--fail-on
//     HIHG` sets the bar at rank 0, so the first INFO finding trips exit 2.
//
// One value, two opposite wrong answers, neither announced. Validation is the
// only thing that distinguishes them from the real ones.
//
// An empty string is not a typo: it means the caller expressed no preference,
// and fallback is the caller's decision rather than this function's.
func resolveSeverity(value string, fallback cloud.Severity) (cloud.Severity, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	normalized := cloud.Severity(strings.ToUpper(strings.TrimSpace(value)))
	for _, accepted := range acceptedSeverities {
		if normalized == accepted {
			return normalized, nil
		}
	}
	names := make([]string, 0, len(acceptedSeverities))
	for _, s := range acceptedSeverities {
		names = append(names, string(s))
	}
	return "", fmt.Errorf("unknown severity %q; want one of: %s", value, strings.Join(names, ", "))
}
