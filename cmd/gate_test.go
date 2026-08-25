package cmd

import (
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compliance"
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

// TestCompliance_UnevaluatedIsNotPassed pins the three-way verdict.
//
// A benchmark run with no input reports grades every control NotEvaluated. The
// gate scored those the same as a pass, so `cloudgov compliance cis-aws-v3
// --fail-on HIGH` reported 0 passed, 0 failed, 22 not evaluated and exited 0 —
// a merge gate reads that as "the benchmark passed".
//
// All three cases are asserted together because each one alone is satisfiable
// by a constant. A gate that always returns 3 passes the first case; a gate that
// never fires passes the second.
func TestCompliance_UnevaluatedIsNotPassed(t *testing.T) {
	ctrl := func(id string, sev cloud.Severity) compliance.Control {
		return compliance.Control{ID: id, Title: "control " + id, Severity: sev}
	}

	tests := []struct {
		name     string
		results  []compliance.ControlResult
		failOn   string
		wantExit int
		why      string
	}{
		{
			name: "nothing could be evaluated is not a pass",
			results: []compliance.ControlResult{
				{Control: ctrl("1.4", cloud.SeverityCritical), Status: compliance.StatusNotEvaluated, Detail: "no IAM findings provided"},
				{Control: ctrl("5.2", cloud.SeverityHigh), Status: compliance.StatusNotEvaluated, Detail: "no network findings provided"},
			},
			failOn:   "HIGH",
			wantExit: 3,
			why:      "the run could not see enough to answer either way",
		},
		{
			// The quiet half. Without this the fix is indistinguishable from a
			// gate that always fires.
			name: "every control evaluated cleanly still exits 0",
			results: []compliance.ControlResult{
				{Control: ctrl("1.4", cloud.SeverityCritical), Status: compliance.StatusPass, Detail: "no root access key"},
				{Control: ctrl("5.2", cloud.SeverityHigh), Status: compliance.StatusPass, Detail: "no open ingress"},
			},
			failOn:   "HIGH",
			wantExit: 0,
			why:      "a fully evaluated, clean benchmark is a pass",
		},
		{
			// A real failure outranks "could not tell": exit 2 is not downgraded.
			name: "a failing control still reports 2, not 3",
			results: []compliance.ControlResult{
				{Control: ctrl("1.16", cloud.SeverityCritical), Status: compliance.StatusFail, Detail: "admin policies found"},
				{Control: ctrl("5.2", cloud.SeverityHigh), Status: compliance.StatusNotEvaluated, Detail: "no network findings provided"},
			},
			failOn:   "HIGH",
			wantExit: 2,
			why:      "a control that failed is a stronger statement than one nobody checked",
		},
		{
			name: "informational run reports nothing",
			results: []compliance.ControlResult{
				{Control: ctrl("1.4", cloud.SeverityCritical), Status: compliance.StatusNotEvaluated, Detail: "no IAM findings provided"},
			},
			failOn:   "",
			wantExit: 0,
			why:      "--fail-on is what declares a run a gate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode = 0
			failOn = tt.failOn
			quiet = true
			t.Cleanup(func() { exitCode = 0; failOn = ""; quiet = false })

			gate(tt.results, func(r compliance.ControlResult) cloud.Severity {
				if r.Status == compliance.StatusFail {
					return r.Control.Severity
				}
				return cloud.SeverityInfo
			})
			var unevaluated []string
			for _, r := range tt.results {
				if r.Status == compliance.StatusNotEvaluated {
					unevaluated = append(unevaluated, r.Control.ID)
				}
			}
			gateIncomplete(unevaluated)

			if exitCode != tt.wantExit {
				t.Errorf("exit code: got %d, want %d — %s", exitCode, tt.wantExit, tt.why)
			}
		})
	}
}

// gate refuses a threshold it cannot rank rather than ranking it at zero.
//
// The root PersistentPreRunE already validates --fail-on, so on every ordinary
// path this branch is unreachable. It exists because the gate is the last place
// to trust an upstream check: ranking an unvalidated string would put the
// threshold at 0, below every real level, and the first INFO finding would exit
// 2 for a reason nobody intended. A gate that fails wrongly teaches its operator
// to stop believing it.
func TestGateRefusesAnUnrankableThreshold(t *testing.T) {
	type item struct{ sev cloud.Severity }
	sev := func(i item) cloud.Severity { return i.sev }
	items := []item{{cloud.SeverityInfo}}

	t.Run("unrankable threshold does not trip the gate", func(t *testing.T) {
		exitCode = 0
		failOn = "HIHG"
		defer func() { failOn = "" }()
		gate(items, sev)
		if exitCode != 0 {
			t.Errorf("exit code = %d; an unrankable threshold must not trip the gate on an INFO finding", exitCode)
		}
	})

	t.Run("a real threshold still trips it", func(t *testing.T) {
		exitCode = 0
		failOn = "INFO"
		defer func() { failOn = "" }()
		gate(items, sev)
		if exitCode != 2 {
			t.Errorf("exit code = %d, want 2 — an INFO finding at an INFO threshold", exitCode)
		}
	})

	t.Run("a threshold above the findings does not", func(t *testing.T) {
		exitCode = 0
		failOn = "HIGH"
		defer func() { failOn = "" }()
		gate(items, sev)
		if exitCode != 0 {
			t.Errorf("exit code = %d; an INFO finding is below a HIGH threshold", exitCode)
		}
	})
}
