package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// restore clean run-state defaults so these globals don't leak into sibling tests.
func restoreRunState(t *testing.T) {
	t.Cleanup(func() { exitCode, failOn, quiet = 0, "", false })
}

func newFlagged() *cobra.Command {
	c := &cobra.Command{}
	c.Flags().String("fail-on", "", "")
	c.Flags().Bool("quiet", false, "")
	return c
}

func TestResetRunState_ClearsWhenFlagsUnset(t *testing.T) {
	restoreRunState(t)
	exitCode, failOn, quiet = 2, "HIGH", true

	resetRunState(newFlagged())

	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	if failOn != "" {
		t.Errorf("failOn = %q, want empty (no --fail-on this run)", failOn)
	}
	if quiet {
		t.Error("quiet = true, want false (no --quiet this run)")
	}
}

func TestResetRunState_PreservesExplicitFlags(t *testing.T) {
	restoreRunState(t)
	exitCode, failOn, quiet = 2, "CRITICAL", true
	cmd := newFlagged()
	_ = cmd.Flags().Set("fail-on", "CRITICAL")
	_ = cmd.Flags().Set("quiet", "true")

	resetRunState(cmd)

	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 (always resets)", exitCode)
	}
	if failOn != "CRITICAL" {
		t.Errorf("failOn = %q, want CRITICAL (explicit --fail-on preserved)", failOn)
	}
	if !quiet {
		t.Error("quiet = false, want true (explicit --quiet preserved)")
	}
}
