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

// The envelope is stable in both directions: an empty findings list is `[]`
// rather than null, and `incomplete` is always present. Without the second, a
// sweep that could not read half an organization renders identically to one that
// read all of it and found nothing.
func TestWriteRepo_EnvelopeIsStable(t *testing.T) {
	var b bytes.Buffer
	if err := WriteRepo(&b, nil, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out struct {
		Findings   *[]cloud.RepoFinding `json:"findings"`
		Total      int                  `json:"total"`
		Incomplete *[]string            `json:"incomplete"`
	}
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("emitted invalid JSON: %v (%s)", err, b.String())
	}
	if out.Findings == nil {
		t.Error("findings is null or absent; a consumer cannot tell clean from did-not-run")
	} else if len(*out.Findings) != 0 {
		t.Errorf("empty sweep reported %d findings", len(*out.Findings))
	}
	if out.Incomplete == nil {
		t.Error("incomplete is null or absent; a complete sweep must say it was complete")
	} else if len(*out.Incomplete) != 0 {
		t.Errorf("a sweep given no unread repositories reported %d", len(*out.Incomplete))
	}
	if strings.TrimSpace(b.String()) == "[]" {
		t.Error("the report is still a bare array; it cannot carry the incomplete record")
	}
}

func TestWriteRepo_RoundTrips(t *testing.T) {
	in := []cloud.RepoFinding{{
		Severity: cloud.SeverityMedium, Type: cloud.RepoAdminsExempt,
		Repo: "eks-gitops", Detail: "enforce_admins is off", Remediation: "Enable it.",
	}}
	var b bytes.Buffer
	if err := WriteRepo(&b, in, []string{"acme/private: settings could not be read"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out struct {
		Findings   []cloud.RepoFinding `json:"findings"`
		Total      int                 `json:"total"`
		Incomplete []string            `json:"incomplete"`
	}
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Findings) != 1 || out.Findings[0].Repo != "eks-gitops" || out.Findings[0].Type != cloud.RepoAdminsExempt {
		t.Errorf("round-trip lost data: %+v", out.Findings)
	}
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if len(out.Incomplete) != 1 {
		t.Errorf("the unread repository did not survive the round trip: %v", out.Incomplete)
	}
}
