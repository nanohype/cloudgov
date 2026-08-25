package compliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// The compliance path carries a 100% file floor, so the branches below are the
// ones a reader would otherwise have to take on trust: which principal a control
// cites, what an unreadable report does, and which CIS control ids the evaluator
// actually recognises.

// A FAIL names the principal when the finding carries one. The reference is what
// an auditor acts on: "full admin" alone does not say whose.
func TestIAMEvaluatorsCitePrincipal(t *testing.T) {
	principal := &cloud.Principal{Name: "svc-deploy", Type: cloud.PrincipalRole}
	for _, tc := range []struct {
		name string
		eval func(Control, []cloud.Finding) ControlResult
		typ  cloud.FindingType
	}{
		{"stale principal", evalStalePrincipal, cloud.FindingStalePrincipal},
		{"broad scope", evalBroadScope, cloud.FindingBroadScope},
		{"admin access", evalAdminAccess, cloud.FindingAdminAccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := Control{ID: "probe"}
			got := tc.eval(ctrl, []cloud.Finding{{Type: tc.typ, Principal: principal, Detail: "detail"}})
			if got.Status != StatusFail {
				t.Fatalf("status = %s, want FAIL", got.Status)
			}
			if len(got.Findings) != 1 || !strings.HasPrefix(got.Findings[0], "svc-deploy: ") {
				t.Errorf("finding does not name the principal: %v", got.Findings)
			}
		})
	}
}

// The same evaluators pass when the findings present are of another kind, which
// is what keeps the FAIL cases above from being satisfied by any input at all.
func TestIAMEvaluatorsPassOnUnrelatedFindings(t *testing.T) {
	unrelated := []cloud.Finding{{Type: cloud.FindingCrossAccountAccess, Detail: "trusts another account"}}
	for _, tc := range []struct {
		name string
		eval func(Control, []cloud.Finding) ControlResult
	}{
		{"stale principal", evalStalePrincipal},
		{"broad scope", evalBroadScope},
		{"admin access", evalAdminAccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.eval(Control{ID: "probe"}, unrelated); got.Status != StatusPass {
				t.Errorf("status = %s, want PASS", got.Status)
			}
		})
	}
}

func TestEvalTagsListsEveryMissingTag(t *testing.T) {
	got := evalTags(Control{ID: "4.1"}, []cloud.TagFinding{
		{ResourceID: "raw-data", MissingTags: []string{"Environment", "Team", "CostCenter"}},
		{ResourceID: "logs", MissingTags: nil},
	})
	if got.Status != StatusFail {
		t.Fatalf("status = %s, want FAIL", got.Status)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("got %d references, want one per finding", len(got.Findings))
	}
	if !strings.Contains(got.Findings[0], "Environment, Team, CostCenter") {
		t.Errorf("missing tags are not listed in order: %q", got.Findings[0])
	}
	// A finding with no missing tags still names its resource; the empty list is
	// what the joiner has to survive.
	if !strings.HasPrefix(got.Findings[1], "logs: missing ") {
		t.Errorf("empty missing-tag list lost its resource: %q", got.Findings[1])
	}
}

// Every CIS control id the evaluator names must reach an evaluator, and an id it
// does not name must decline. A silently unrecognised id would report
// NOT_EVALUATED on a control the benchmark believes it covers.
func TestEvaluateCISAWSDispatch(t *testing.T) {
	input := InputFindings{
		IAM:     []cloud.Finding{{Type: cloud.FindingAdminAccess, Detail: "full admin"}},
		Storage: []cloud.BucketFinding{{Type: cloud.BucketPublicAccess, Bucket: "docs"}},
		Network: []cloud.NetworkFinding{{Type: cloud.NetworkAdminPortOpen, Resource: "sg-1"}},
		Tags:    []cloud.TagFinding{{ResourceID: "raw", MissingTags: []string{"Team"}}},
		Certs:   []cloud.CertFinding{{Status: cloud.CertExpired, Domain: "api.example.test"}},
	}
	recognised := []string{
		"1.16", "1.10", "1.12", "1.15", "1.4", "1.5", "1.17", "1.19", "1.22",
		"2.1.4", "2.1.5", "2.1.1", "2.1.2", "2.2.1",
		"3.7", "3.1", "3.4",
		"4.1",
		"5.1", "5.2", "5.3", "5.4",
	}
	for _, id := range recognised {
		t.Run(id, func(t *testing.T) {
			got := evaluateCISAWS(Control{ID: id}, input)
			if got.Detail == "no evaluator for this control" {
				t.Errorf("control %s fell through to the default arm", id)
			}
		})
	}
	t.Run("unrecognised", func(t *testing.T) {
		got := evaluateCISAWS(Control{ID: "9.9"}, input)
		if got.Status != StatusNotEvaluated || got.Detail != "no evaluator for this control" {
			t.Errorf("an unrecognised control did not decline: %+v", got)
		}
	})
}

// A report the loader cannot read is an error, never an empty finding list: an
// empty list would make an unreadable file indistinguishable from a clean domain,
// and every control mapped to that domain would then read NOT_EVALUATED.
func TestLoadersRejectUnreadableReports(t *testing.T) {
	loaders := map[string]func(string) error{
		"iam":     func(p string) error { _, _, err := LoadIAMReport(p); return err },
		"storage": func(p string) error { _, _, err := LoadStorageReport(p); return err },
		"network": func(p string) error { _, _, err := LoadNetworkReport(p); return err },
		"certs":   func(p string) error { _, _, err := LoadCertsReport(p); return err },
		"tags":    func(p string) error { _, _, err := LoadTagsReport(p); return err },
	}
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"findings": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "absent.json")

	for domain, load := range loaders {
		t.Run(domain+"/missing file", func(t *testing.T) {
			err := load(missing)
			if err == nil {
				t.Fatal("a missing report loaded without error")
			}
			if !strings.Contains(err.Error(), "read ") {
				t.Errorf("error does not say the read failed: %v", err)
			}
		})
		t.Run(domain+"/malformed json", func(t *testing.T) {
			err := load(malformed)
			if err == nil {
				t.Fatal("a truncated report loaded without error")
			}
			if !strings.Contains(err.Error(), "parse ") {
				t.Errorf("error does not say the parse failed: %v", err)
			}
		})
	}
}

func TestAvailableBenchmarksAllResolve(t *testing.T) {
	ids := AvailableBenchmarks()
	if len(ids) == 0 {
		t.Fatal("AvailableBenchmarks is empty; no benchmark can be selected")
	}
	for _, id := range ids {
		if b := GetBenchmark(id); b == nil {
			t.Errorf("AvailableBenchmarks names %q but GetBenchmark returns nil for it", id)
		}
	}
	if GetBenchmark("not-a-benchmark") != nil {
		t.Error("GetBenchmark returned a benchmark for an unknown id")
	}
}
