package compliance

import (
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestEvaluateAdminAccess(t *testing.T) {
	benchmark := GetBenchmark("cis-aws-v3")
	if benchmark == nil {
		t.Fatal("benchmark not found")
	}

	tests := []struct {
		name       string
		input      InputFindings
		controlID  string
		wantStatus ControlStatus
	}{
		{
			name: "admin access found fails control 1.16",
			input: InputFindings{
				IAM: []cloud.Finding{
					{Type: cloud.FindingAdminAccess, Severity: cloud.SeverityCritical, Detail: "full admin", Principal: &cloud.Principal{Name: "admin-user"}},
				},
			},
			controlID:  "1.16",
			wantStatus: StatusFail,
		},
		{
			name: "no admin access passes control 1.16",
			input: InputFindings{
				IAM: []cloud.Finding{
					{Type: cloud.FindingUnusedPermission, Severity: cloud.SeverityMedium, Detail: "unused perm"},
				},
			},
			controlID:  "1.16",
			wantStatus: StatusPass,
		},
		{
			name:       "no IAM findings gives not evaluated",
			input:      InputFindings{},
			controlID:  "1.16",
			wantStatus: StatusNotEvaluated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := Evaluate(benchmark, tt.input)
			for _, r := range report.Results {
				if r.Control.ID == tt.controlID {
					if r.Status != tt.wantStatus {
						t.Errorf("control %s: got %s, want %s", tt.controlID, r.Status, tt.wantStatus)
					}
					return
				}
			}
			t.Errorf("control %s not found in results", tt.controlID)
		})
	}
}

func TestEvaluateStorageControls(t *testing.T) {
	benchmark := GetBenchmark("cis-aws-v3")

	tests := []struct {
		name       string
		input      InputFindings
		controlID  string
		wantStatus ControlStatus
	}{
		{
			name: "unencrypted bucket fails 2.1.4",
			input: InputFindings{
				Storage: []cloud.BucketFinding{
					{Type: cloud.BucketUnencrypted, Bucket: "test-bucket", Severity: cloud.SeverityHigh},
				},
			},
			controlID:  "2.1.4",
			wantStatus: StatusFail,
		},
		{
			name: "public access fails 2.1.5",
			input: InputFindings{
				Storage: []cloud.BucketFinding{
					{Type: cloud.BucketPublicAccess, Bucket: "pub-bucket", Severity: cloud.SeverityCritical},
				},
			},
			controlID:  "2.1.5",
			wantStatus: StatusFail,
		},
		{
			name: "no public access passes 2.1.5",
			input: InputFindings{
				Storage: []cloud.BucketFinding{
					{Type: cloud.BucketNoVersioning, Bucket: "other", Severity: cloud.SeverityMedium},
				},
			},
			controlID:  "2.1.5",
			wantStatus: StatusPass,
		},
		{
			name:       "no storage findings gives not evaluated",
			input:      InputFindings{},
			controlID:  "2.1.4",
			wantStatus: StatusNotEvaluated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := Evaluate(benchmark, tt.input)
			for _, r := range report.Results {
				if r.Control.ID == tt.controlID {
					if r.Status != tt.wantStatus {
						t.Errorf("control %s: got %s, want %s", tt.controlID, r.Status, tt.wantStatus)
					}
					return
				}
			}
			t.Errorf("control %s not found in results", tt.controlID)
		})
	}
}

func TestEvaluateNetworkControls(t *testing.T) {
	benchmark := GetBenchmark("cis-aws-v3")

	tests := []struct {
		name       string
		input      InputFindings
		controlID  string
		wantStatus ControlStatus
	}{
		{
			name: "admin port open fails 5.1",
			input: InputFindings{
				Network: []cloud.NetworkFinding{
					{Type: cloud.NetworkAdminPortOpen, Resource: "sg-123", Detail: "port 22 open"},
				},
			},
			controlID:  "5.1",
			wantStatus: StatusFail,
		},
		{
			name: "no admin ports passes 5.2",
			input: InputFindings{
				Network: []cloud.NetworkFinding{
					{Type: cloud.NetworkOpenIngress, Resource: "sg-456", Detail: "port 80 open"},
				},
			},
			controlID:  "5.2",
			wantStatus: StatusPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := Evaluate(benchmark, tt.input)
			for _, r := range report.Results {
				if r.Control.ID == tt.controlID {
					if r.Status != tt.wantStatus {
						t.Errorf("control %s: got %s, want %s", tt.controlID, r.Status, tt.wantStatus)
					}
					return
				}
			}
			t.Errorf("control %s not found in results", tt.controlID)
		})
	}
}

func TestEvaluateSummary(t *testing.T) {
	benchmark := GetBenchmark("cis-aws-v3")
	report := Evaluate(benchmark, InputFindings{
		IAM: []cloud.Finding{
			{Type: cloud.FindingAdminAccess, Severity: cloud.SeverityCritical, Detail: "admin"},
		},
		Storage: []cloud.BucketFinding{
			{Type: cloud.BucketPublicAccess, Bucket: "pub", Severity: cloud.SeverityCritical},
		},
	})

	if report.Summary.Total != len(benchmark.Controls) {
		t.Errorf("summary total: got %d, want %d", report.Summary.Total, len(benchmark.Controls))
	}
	if report.Summary.Passed+report.Summary.Failed+report.Summary.NotEvaluated != report.Summary.Total {
		t.Error("summary counts don't add up to total")
	}
	if report.Summary.Failed == 0 {
		t.Error("expected at least one failure")
	}
}

func TestEvaluateTagsControl(t *testing.T) {
	benchmark := GetBenchmark("cis-aws-v3")
	report := Evaluate(benchmark, InputFindings{
		Tags: []cloud.TagFinding{
			{ResourceID: "i-123", MissingTags: []string{"env", "owner"}},
		},
	})

	for _, r := range report.Results {
		if r.Control.ID == "4.1" {
			if r.Status != StatusFail {
				t.Errorf("control 4.1: got %s, want FAIL", r.Status)
			}
			if len(r.Findings) != 1 {
				t.Errorf("control 4.1: got %d findings, want 1", len(r.Findings))
			}
			return
		}
	}
	t.Error("control 4.1 not found")
}

// The two generic evaluators serve controls a scan is evidence toward but does
// not decide, and they must never report PASS. PASS is what an auditor reads as
// "examined and clean", and neither evaluator examined anything: it returns a
// verdict about a control on the strength of findings about a different one.
//
// Both branches are pinned, because the branch that matters is the one that runs
// when a scan DID find something — an evaluator that declines only on an empty
// input still hands out a verdict on the path an operator actually takes.
// Statement coverage cannot see the difference: returning
// `ControlResult{Control: ctrl, Status: StatusPass, ...}` executes the same one
// statement the decline does, and the file's 100 floor is met either way.
func TestGenericEvaluatorsNeverReportAVerdict(t *testing.T) {
	ctrl := Control{ID: "2.1.1", Title: "a control nothing examined"}

	declines := map[string]func(withFindings bool) ControlResult{
		"evalStorageGeneric": func(withFindings bool) ControlResult {
			var findings []cloud.BucketFinding
			if withFindings {
				findings = []cloud.BucketFinding{{Type: cloud.BucketPublicAccess, Bucket: "docs"}}
			}
			return evalStorageGeneric(ctrl, findings)
		},
		"evalIAMGeneric": func(withFindings bool) ControlResult {
			var findings []cloud.Finding
			if withFindings {
				findings = []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin"}}
			}
			return evalIAMGeneric(ctrl, findings)
		},
	}

	for name, evaluate := range declines {
		for _, withFindings := range []bool{false, true} {
			label := "no findings loaded"
			if withFindings {
				label = "findings loaded for the domain"
			}
			t.Run(name+"/"+label, func(t *testing.T) {
				got := evaluate(withFindings)
				if got.Status != StatusNotEvaluated {
					t.Fatalf("status = %s, want NOT_EVALUATED — this evaluator examined nothing "+
						"and a verdict here is a claim the tool cannot compute: %+v", got.Status, got)
				}
				if got.Detail == "" {
					t.Error("the decline carries no reason, so a reader cannot tell why the tool declined")
				}
			})
		}
	}
}

// A control's Description and its Status travel in the same JSON, and an auditor
// reads both. A control whose shipped description says it is reported as not
// evaluated must in fact report that, or the artifact contradicts itself in a way
// only someone reading both fields can see.
//
// The population is read from the shipped descriptions, so a control that makes
// the promise is covered by making it. This is not a claim that any benchmark
// contains one — a benchmark that promises nothing contributes nothing here, and
// what holds the evaluators regardless of prose is
// TestGenericEvaluatorsNeverReportAVerdict above.
func TestEveryControlPromisingNoVerdictReportsNone(t *testing.T) {
	// Findings in every domain, so a control that declines only on an empty
	// input cannot satisfy this by accident.
	loaded := InputFindings{
		IAM:     []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin", Detail: "full admin"}},
		Storage: []cloud.BucketFinding{{Type: cloud.BucketPublicAccess, Bucket: "docs"}},
		Network: []cloud.NetworkFinding{{Type: cloud.NetworkAdminPortOpen, Resource: "sg-1"}},
		Tags:    []cloud.TagFinding{{ResourceID: "raw", MissingTags: []string{"Team"}}},
		Certs:   []cloud.CertFinding{{Status: cloud.CertExpired, Domain: "api.example.test"}},
	}

	const promise = "reported as not evaluated"
	promising := 0
	for _, id := range AvailableBenchmarks() {
		benchmark := GetBenchmark(id)
		if benchmark == nil {
			t.Fatalf("benchmark %s is published and does not resolve", id)
		}
		for _, result := range Evaluate(benchmark, loaded).Results {
			if !strings.Contains(result.Control.Description, promise) {
				continue
			}
			promising++
			if result.Status != StatusNotEvaluated {
				t.Errorf("%s %s reports %s while its own description, in the same report, says it is "+
					"%s — an auditor reading the two fields is told opposite things",
					id, result.Control.ID, result.Status, promise)
			}
		}
	}

	if promising == 0 {
		t.Fatalf("no published control's description contains %q; the population is empty, which is "+
			"not the same as every promise being kept", promise)
	}
}
