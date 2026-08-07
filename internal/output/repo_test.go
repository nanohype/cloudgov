package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestRepoFindings_EmptyIsExplicitlyClean(t *testing.T) {
	var b bytes.Buffer
	RepoFindings(&b, nil)
	if !strings.Contains(b.String(), "✓") {
		t.Errorf("an empty result must state that it is clean, not print nothing: %q", b.String())
	}
}

func TestRepoFindings_PrintsTheRemediationInFull(t *testing.T) {
	var b bytes.Buffer
	RepoFindings(&b, []cloud.RepoFinding{{
		Severity: cloud.SeverityHigh,
		Type:     cloud.RepoNoRequiredChecks,
		Repo:     "landing-zone",
		Detail:   "a protection rule exists and requires no status check",
		// The useful half of these findings is usually the caveat, so it must
		// not be truncated the way a table cell would.
		Remediation: "Add the repository's required checks. This state is worse than no rule.",
	}})
	got := b.String()
	for _, want := range []string{"landing-zone", "NO_REQUIRED_CHECKS", "worse than no rule"} {
		if !strings.Contains(got, want) {
			t.Errorf("output must contain %q, got:\n%s", want, got)
		}
	}
}

func TestWriteRepo_EmptyIsAnArrayNotNull(t *testing.T) {
	// A consumer distinguishing "clean" from "did not run" needs a stable shape.
	var b bytes.Buffer
	if err := WriteRepo(&b, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out []cloud.RepoFinding
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("emitted invalid JSON: %v (%s)", err, b.String())
	}
	if strings.TrimSpace(b.String()) != "[]" {
		t.Errorf("empty findings must serialize as [], got %q", strings.TrimSpace(b.String()))
	}
}

func TestWriteRepo_RoundTrips(t *testing.T) {
	in := []cloud.RepoFinding{{
		Severity: cloud.SeverityMedium, Type: cloud.RepoAdminsExempt,
		Repo: "eks-gitops", Detail: "enforce_admins is off", Remediation: "Enable it.",
	}}
	var b bytes.Buffer
	if err := WriteRepo(&b, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out []cloud.RepoFinding
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != 1 || out[0].Repo != "eks-gitops" || out[0].Type != cloud.RepoAdminsExempt {
		t.Errorf("round-trip lost data: %+v", out)
	}
}
