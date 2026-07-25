package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/spf13/cobra"
)

// exitCode is the process exit status returned by Execute. 0 means clean (or
// --fail-on was not set); 2 means at least one finding met or exceeded the
// --fail-on severity threshold; 3 means the scan could not observe everything it
// was asked to, so its result is not evidence either way. Exit code 1 is
// reserved for command errors and is set directly in Execute.
var exitCode int

// failOn holds the --fail-on severity threshold (CRITICAL/HIGH/MEDIUM/LOW).
// Empty means findings never affect the exit code.
var failOn string

// gate raises the exit code to 2 when --fail-on is set and any item's severity
// (extracted via sev) meets or exceeds the threshold. No-op when --fail-on is
// empty, so default behaviour is unchanged.
func gate[T any](items []T, sev func(T) cloud.Severity) {
	if failOn == "" {
		return
	}
	threshold := cloud.SeverityRank(cloud.Severity(strings.ToUpper(failOn)))
	for _, it := range items {
		if cloud.SeverityRank(sev(it)) >= threshold {
			exitCode = 2
			return
		}
	}
}

// gateBool raises the exit code to 2 when --fail-on is set and cond is true. For
// domains without a per-finding severity (e.g. drift), any qualifying finding
// trips the gate regardless of the threshold value.
func gateBool(cond bool) {
	if failOn != "" && cond {
		exitCode = 2
	}
}

// gateIncomplete reports the observations a scan could not complete, and raises
// the exit code to 3 when --fail-on is set.
//
// Passing --fail-on declares that this run is a gate, and a gate that could not
// read part of the account must not answer "clean" — cloudgov's exit 0 is
// consumed as evidence supporting approval, so an unread bucket or an unreadable
// principal has to be distinguishable from an audited one. It does not override
// an existing failure: findings that already tripped the threshold are the
// stronger signal, so exit 2 stands.
//
// Without --fail-on the run is informational and the exit code stays 0; the
// messages still go to stderr and to the JSON report.
func gateIncomplete(incomplete []string) {
	if len(incomplete) == 0 {
		return
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "\nincomplete: %d observation(s) could not be completed; findings are a partial view\n", len(incomplete))
		for _, w := range incomplete {
			fmt.Fprintf(os.Stderr, "  - %s\n", w)
		}
	}
	if failOn != "" && exitCode == 0 {
		exitCode = 3
	}
}

// resetRunState clears run-scoped state so the command tree is safe to drive
// repeatedly in one process (the MCP server and agent loops re-run commands
// without a fresh os.Exit). The exit code always resets; the persistent flag
// vars reset only when the flag wasn't passed this run, so an explicit
// --fail-on / --quiet still wins and an omitted one can't leak from a prior run.
func resetRunState(cmd *cobra.Command) {
	exitCode = 0
	if !cmd.Flags().Changed("fail-on") {
		failOn = ""
	}
	if !cmd.Flags().Changed("quiet") {
		quiet = false
	}
}
