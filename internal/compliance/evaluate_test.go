package compliance

import (
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
