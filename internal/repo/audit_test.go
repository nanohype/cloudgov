package repo

import (
	"context"
	"errors"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// fakeReader stands in for GitHub. The audit owns its Reader interface for
// exactly this reason: the whole thing runs against fixtures, with no token and
// no network, so the cases below are the real org state observed on 2026-08-07
// rather than a shape invented to be easy to assert.
type fakeReader struct {
	repos    []string
	settings map[string]cloud.RepoSettings
	errs     map[string]error
	listErr  error
}

func (f *fakeReader) ListRepos(_ context.Context, _ string) ([]string, error) {
	return f.repos, f.listErr
}

func (f *fakeReader) Settings(_ context.Context, _, repo string) (cloud.RepoSettings, error) {
	if err, ok := f.errs[repo]; ok {
		return cloud.RepoSettings{}, err
	}
	s, ok := f.settings[repo]
	if !ok {
		return cloud.RepoSettings{}, errors.New("no fixture")
	}
	return s, nil
}

func defaults() Expected {
	return Expected{
		EnforceAdmins:          true,
		AllowForcePushes:       false,
		AllowDeletions:         false,
		AlertsEnabled:          true,
		SecurityUpdatesEnabled: true,
		Exempt:                 map[string]string{},
	}
}

func typesOf(fs []cloud.RepoFinding) map[cloud.RepoFindingType]int {
	out := map[cloud.RepoFindingType]int{}
	for _, f := range fs {
		out[f.Type]++
	}
	return out
}

func healthy(name string) cloud.RepoSettings {
	return cloud.RepoSettings{
		Name: name, DefaultRef: "main", Protected: true,
		RequiredChecks: []string{"build"}, EnforceAdmins: true,
		AlertsEnabled: true, SecurityUpdatesEnabled: true,
	}
}

// TestAudit_ProtectedButRequiresNothing is the state this whole command exists
// for. landing-zone, cloudgov and homebrew-tap were all here: a protection rule
// on main requiring zero status checks, so the repository reads as protected in
// every UI and admits a PR whose entire CI matrix is red. On landing-zone that
// merge becomes live AWS infrastructure.
func TestAudit_ProtectedButRequiresNothing(t *testing.T) {
	r := &fakeReader{
		repos: []string{"landing-zone"},
		settings: map[string]cloud.RepoSettings{
			"landing-zone": {
				Name: "landing-zone", DefaultRef: "main", Protected: true,
				RequiredChecks: nil, EnforceAdmins: false,
				AlertsEnabled: true, SecurityUpdatesEnabled: true,
			},
		},
	}
	got, err := Audit(context.Background(), r, "nanohype", defaults())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	counts := typesOf(got)
	if counts[cloud.RepoNoRequiredChecks] != 1 {
		t.Errorf("a protection rule with no required checks must be reported: %+v", counts)
	}
	if counts[cloud.RepoNoProtection] != 0 {
		t.Errorf("a rule that exists must NOT be reported as absent — the two are different "+
			"facts and get fixed differently: %+v", counts)
	}
	if counts[cloud.RepoAdminsExempt] != 1 {
		t.Errorf("enforce_admins off must be reported alongside it: %+v", counts)
	}
}

// TestAudit_UnprotectableIsNotCompliant covers clusters, tenants and
// nanohype.dev: private repos on the free plan, where the API refuses protection
// outright. No setting fixes it, and silence would read as compliance — on the
// two repositories holding live cluster and tenant GitOps state.
func TestAudit_UnprotectableIsNotCompliant(t *testing.T) {
	r := &fakeReader{
		repos: []string{"tenants"},
		settings: map[string]cloud.RepoSettings{
			"tenants": {
				Name: "tenants", Private: true, DefaultRef: "main",
				ProtectionUnavailable: true,
				AlertsEnabled:         true, SecurityUpdatesEnabled: true,
			},
		},
	}
	got, _ := Audit(context.Background(), r, "nanohype", defaults())
	counts := typesOf(got)
	if counts[cloud.RepoUnprotectable] != 1 {
		t.Fatalf("an unprotectable repository must be reported, not passed over: %+v", counts)
	}
	if counts[cloud.RepoNoProtection] != 0 {
		t.Errorf("unavailable-on-plan is not the same finding as unprotected-by-choice: %+v", counts)
	}
}

// TestAudit_MissingRequiredCheck proves the expected shape is actually compared
// rather than merely parsed.
func TestAudit_MissingRequiredCheck(t *testing.T) {
	s := healthy("eks-gitops")
	s.RequiredChecks = []string{"lint"}
	r := &fakeReader{repos: []string{"eks-gitops"}, settings: map[string]cloud.RepoSettings{"eks-gitops": s}}

	exp := defaults()
	exp.RequiredChecks = map[string][]string{"eks-gitops": {"lint", "validate", "kyverno"}}

	got, _ := Audit(context.Background(), r, "nanohype", exp)
	counts := typesOf(got)
	if counts[cloud.RepoMissingRequiredCheck] != 1 {
		t.Fatalf("missing expected checks must be reported: %+v", counts)
	}
	if len(got) > 0 && !contains(got[0].Detail, "validate") {
		t.Errorf("the finding must name which checks are missing, got %q", got[0].Detail)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestAudit_UnreadableRepoIsReportedNotSkipped is the anti-vacuity rule. A sweep
// that skips what it cannot read reports a clean org over repositories it never
// looked at — the same shape as every defect this tool is pointed at.
func TestAudit_UnreadableRepoIsReportedNotSkipped(t *testing.T) {
	r := &fakeReader{
		repos:    []string{"portal"},
		settings: map[string]cloud.RepoSettings{},
		errs:     map[string]error{"portal": errors.New("404 Not Found")},
	}
	got, err := Audit(context.Background(), r, "nanohype", defaults())
	if err != nil {
		t.Fatalf("one unreadable repo must not fail the whole sweep: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("an unreadable repository must produce a finding, got %d", len(got))
	}
}

// TestAudit_ExemptAndArchivedAreSkipped, and nothing else is.
func TestAudit_ExemptAndArchivedAreSkipped(t *testing.T) {
	bad := cloud.RepoSettings{Name: "old", DefaultRef: "main", Archived: true}
	r := &fakeReader{
		repos: []string{"old", "skipme", "watched"},
		settings: map[string]cloud.RepoSettings{
			"old":     bad,
			"skipme":  {Name: "skipme", DefaultRef: "main"},
			"watched": {Name: "watched", DefaultRef: "main"},
		},
	}
	exp := defaults()
	exp.Exempt = map[string]string{"skipme": "a template repo with no delivery path"}

	got, _ := Audit(context.Background(), r, "nanohype", exp)
	for _, f := range got {
		if f.Repo == "old" || f.Repo == "skipme" {
			t.Errorf("%s must be skipped, got %s", f.Repo, f.Type)
		}
	}
	if len(got) == 0 {
		t.Fatal("the un-exempt unprotected repo must still be reported — this test would " +
			"otherwise pass by skipping everything")
	}
}

// TestAudit_HealthyRepoIsSilent. Without this the assertions above pass on a
// function that flags everything.
func TestAudit_HealthyRepoIsSilent(t *testing.T) {
	r := &fakeReader{
		repos:    []string{"fab"},
		settings: map[string]cloud.RepoSettings{"fab": healthy("fab")},
	}
	got, _ := Audit(context.Background(), r, "nanohype", defaults())
	if len(got) != 0 {
		t.Errorf("a conforming repository must produce no findings, got %+v", got)
	}
}

// TestAudit_DependabotGaps covers the half that alerting alone does not: alerts
// enabled with security updates off means every patchable advisory waits on a
// human noticing it, so the repository reports as watched while nothing acts on
// what it sees.
func TestAudit_DependabotGaps(t *testing.T) {
	s := healthy("docs")
	s.SecurityUpdatesEnabled = false
	s.OpenAlerts = 3
	r := &fakeReader{repos: []string{"docs"}, settings: map[string]cloud.RepoSettings{"docs": s}}

	got, _ := Audit(context.Background(), r, "nanohype", defaults())
	counts := typesOf(got)
	if counts[cloud.RepoSecurityUpdatesDisabled] != 1 {
		t.Errorf("security updates off must be reported: %+v", counts)
	}
	if counts[cloud.RepoOpenAlerts] != 1 {
		t.Errorf("open alerts must be reported: %+v", counts)
	}
}

// TestAudit_ListFailureIsAnError — a sweep that cannot enumerate the org has not
// found nothing, it has found out nothing.
func TestAudit_ListFailureIsAnError(t *testing.T) {
	r := &fakeReader{listErr: errors.New("401 Bad credentials")}
	if _, err := Audit(context.Background(), r, "nanohype", defaults()); err == nil {
		t.Fatal("a failed org listing must be an error, not an empty clean report")
	}
}
