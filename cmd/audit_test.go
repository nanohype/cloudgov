package cmd

import (
	"testing"

	"github.com/nanohype/cloudgov/internal/audit"
)

// TestAudit_PartialViewRaisesTheIncompleteExitCode holds the aggregate audit to
// the same contract every per-domain command already keeps.
//
// `cloudgov audit` is the widest scan the tool offers — all seven domains in one
// run — which makes it the one most likely to be pointed at an account it cannot
// fully read, and the one whose exit code a merge gate is most likely to consume.
// Exit 0 there affirmatively supports approval, so a run that could not read part
// of the account has to say so rather than argue the unread part was fine.
func TestAudit_PartialViewRaisesTheIncompleteExitCode(t *testing.T) {
	t.Cleanup(func() { exitCode, failOn, quiet = 0, "", false })

	report := &audit.Report{
		Incomplete: []string{"iam: list roles page 2: AccessDenied"},
	}

	exitCode, failOn, quiet = 0, "HIGH", true
	gateIncomplete(report.Incomplete)

	if exitCode != 3 {
		t.Errorf("a partial audit exited %d, want 3 (incomplete)", exitCode)
	}
}

// A fully-observed audit must not be downgraded — otherwise every clean run
// looks inconclusive and the exit code stops carrying information.
func TestAudit_CompleteScanKeepsItsExitCode(t *testing.T) {
	t.Cleanup(func() { exitCode, failOn, quiet = 0, "", false })

	report := &audit.Report{}

	exitCode, failOn, quiet = 0, "HIGH", true
	gateIncomplete(report.Incomplete)

	if exitCode != 0 {
		t.Errorf("a complete audit exited %d, want 0", exitCode)
	}
}
