package cmd

import (
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestGate(t *testing.T) {
	tests := []struct {
		name   string
		failOn string
		sevs   []cloud.Severity
		want   int
	}{
		{"disabled ignores findings", "", []cloud.Severity{cloud.SeverityCritical}, 0},
		{"below threshold", "CRITICAL", []cloud.Severity{cloud.SeverityHigh}, 0},
		{"at threshold", "HIGH", []cloud.Severity{cloud.SeverityLow, cloud.SeverityHigh}, 2},
		{"above threshold", "MEDIUM", []cloud.Severity{cloud.SeverityCritical}, 2},
		{"lowercase flag", "high", []cloud.Severity{cloud.SeverityHigh}, 2},
		{"no findings", "LOW", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode = 0
			failOn = tt.failOn
			gate(tt.sevs, func(s cloud.Severity) cloud.Severity { return s })
			if exitCode != tt.want {
				t.Errorf("exitCode = %d, want %d", exitCode, tt.want)
			}
		})
	}
	exitCode = 0
	failOn = ""
}

func TestGateBool(t *testing.T) {
	t.Cleanup(func() { exitCode = 0; failOn = "" })

	exitCode, failOn = 0, ""
	gateBool(true)
	if exitCode != 0 {
		t.Errorf("gateBool with --fail-on unset must not gate, got %d", exitCode)
	}

	failOn = "LOW"
	gateBool(false)
	if exitCode != 0 {
		t.Errorf("gateBool(false) must not gate, got %d", exitCode)
	}
	gateBool(true)
	if exitCode != 2 {
		t.Errorf("gateBool(true) with --fail-on set must gate to 2, got %d", exitCode)
	}
}

// TestGateIncomplete pins the exit-code contract for a scan that could not
// observe everything. The distinction it encodes is the whole point: exit 0 is
// read as evidence supporting approval, so a run that did not see part of the
// account must be distinguishable from one that saw it all and found nothing.
func TestGateIncomplete(t *testing.T) {
	t.Cleanup(func() { exitCode, failOn, quiet = 0, "", false })

	tests := []struct {
		name       string
		failOn     string
		startExit  int
		incomplete []string
		want       int
	}{
		{
			// A complete run must not trip the gate — the signal is only
			// meaningful if silence means "saw everything".
			name: "nothing incomplete is clean", failOn: "HIGH",
			incomplete: nil, want: 0,
		},
		{
			// Without --fail-on the run is informational, not a gate. The
			// messages still reach stderr and the JSON report; the exit code
			// does not move.
			name: "informational run stays 0", failOn: "",
			incomplete: []string{"list roles page: AccessDenied"}, want: 0,
		},
		{
			name: "gated run reports incomplete", failOn: "HIGH",
			incomplete: []string{"list roles page: AccessDenied"}, want: 3,
		},
		{
			// Findings that already tripped the threshold are the stronger
			// signal: a scan that found a Critical AND could not read part of
			// the account is still a REJECT, not an "inconclusive".
			name: "does not downgrade an existing failure", failOn: "HIGH",
			startExit: 2, incomplete: []string{"bucket x: versioning check failed"}, want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, failOn, quiet = tt.startExit, tt.failOn, true
			gateIncomplete(tt.incomplete)
			if exitCode != tt.want {
				t.Errorf("exitCode = %d, want %d", exitCode, tt.want)
			}
		})
	}
}

// TestGateIncomplete_QuietSilencesOutputNotTheGate: --quiet is about noise. A
// scan that could not read part of the account is still incomplete, so the exit
// code must be identical either way.
func TestGateIncomplete_QuietSilencesOutputNotTheGate(t *testing.T) {
	t.Cleanup(func() { exitCode, failOn, quiet = 0, "", false })
	incomplete := []string{"list roles page: AccessDenied"}

	exitCode, failOn, quiet = 0, "HIGH", false
	gateIncomplete(incomplete)
	loud := exitCode

	exitCode, quiet = 0, true
	gateIncomplete(incomplete)

	if loud != 3 || exitCode != 3 {
		t.Errorf("exit code differed with --quiet: loud=%d quiet=%d, want 3 and 3", loud, exitCode)
	}
}
