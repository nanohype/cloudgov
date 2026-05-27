package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compliance"
)

// renderedContains is the standard assertion for these renderer smoke tests:
// render the report to a buffer and check that key content markers appear.
// We don't pin lipgloss output (which varies with terminal width) — we just
// confirm each rendered field actually makes it through.
func assertContains(t *testing.T, buf *bytes.Buffer, wantSubstrings ...string) {
	t.Helper()
	got := buf.String()
	for _, want := range wantSubstrings {
		if !strings.Contains(got, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, got)
		}
	}
}

func TestIAMFindings_Empty(t *testing.T) {
	var buf bytes.Buffer
	IAMFindings(&buf, nil, 0)
	assertContains(t, &buf, "no findings")
}

func TestIAMFindings_RendersFinding(t *testing.T) {
	var buf bytes.Buffer
	IAMFindings(&buf, []cloud.Finding{{
		Severity:  cloud.SeverityCritical,
		Type:      cloud.FindingAdminAccess,
		Provider:  "aws",
		Principal: &cloud.Principal{Name: "admin"},
		Detail:    "wildcard action",
	}}, 5)
	assertContains(t, &buf, "admin", "wildcard action", "5")
}

func TestBucketFindings(t *testing.T) {
	var buf bytes.Buffer
	BucketFindings(&buf, []cloud.BucketFinding{{
		Severity: cloud.SeverityCritical, Type: cloud.BucketPublicAccess,
		Provider: "aws", Bucket: "leaky", Region: "us-east-1",
		Detail: "publicly accessible",
	}})
	assertContains(t, &buf, "leaky", "publicly accessible")
}

func TestBucketFindings_Empty(t *testing.T) {
	var buf bytes.Buffer
	BucketFindings(&buf, nil)
	if buf.Len() == 0 {
		t.Error("empty findings should still produce some output")
	}
}

func TestOrphanResources(t *testing.T) {
	var buf bytes.Buffer
	OrphanResources(&buf, []cloud.OrphanResource{
		{Kind: cloud.OrphanDisk, ID: "vol-1", Name: "stale", Region: "us-east-1",
			Provider: "aws", MonthlyCost: 10.0},
	})
	assertContains(t, &buf, "stale", "TOTAL", "$10.00")
}

func TestCostDiffs(t *testing.T) {
	var buf bytes.Buffer
	CostDiffs(&buf, []cloud.CostDiff{{
		Provider: "aws",
		Entries: []cloud.CostDiffEntry{
			{Service: "EC2", Before: 100, After: 150, Delta: 50, PctChange: 50},
		},
	}})
	assertContains(t, &buf, "EC2", "aws")
}

func TestNetworkFindings(t *testing.T) {
	var buf bytes.Buffer
	NetworkFindings(&buf, []cloud.NetworkFinding{{
		Severity: cloud.SeverityCritical, Type: cloud.NetworkAdminPortOpen,
		Provider: "aws", Resource: "sg-1", Port: "22", Protocol: "tcp",
		Detail: "SSH open",
	}})
	assertContains(t, &buf, "sg-1", "22", "SSH open")
}

func TestCertFindings(t *testing.T) {
	var buf bytes.Buffer
	CertFindings(&buf, []cloud.CertFinding{{
		Severity: cloud.SeverityHigh, Provider: "aws",
		Domain: "example.com", DaysLeft: 7,
	}})
	assertContains(t, &buf, "example.com")
}

func TestTagFindings(t *testing.T) {
	var buf bytes.Buffer
	TagFindings(&buf, []cloud.TagFinding{{
		Severity: cloud.SeverityMedium, Provider: "aws",
		ResourceID: "i-1", ResourceType: "ec2:instance",
		MissingTags: []string{"owner"},
	}})
	assertContains(t, &buf, "i-1", "owner")
}

func TestDriftResults(t *testing.T) {
	var buf bytes.Buffer
	DriftResults(&buf, []cloud.DriftResult{{
		ResourceType: "aws_security_group", ResourceID: "sg-1",
		Status: cloud.DriftModified,
		Fields: []cloud.DriftField{{Field: "name", Expected: "a", Actual: "b"}},
	}})
	assertContains(t, &buf, "sg-1")
}

func TestComplianceReport(t *testing.T) {
	var buf bytes.Buffer
	ComplianceReport(&buf, compliance.ComplianceReport{
		Benchmark: "CIS AWS v3",
		Results: []compliance.ControlResult{
			{Control: compliance.Control{ID: "1.1", Title: "MFA on root"}, Status: compliance.StatusPass},
			{Control: compliance.Control{ID: "1.2", Title: "No public buckets"}, Status: compliance.StatusFail},
		},
		Summary: compliance.ComplianceSummary{Passed: 1, Failed: 1, Total: 2},
	})
	assertContains(t, &buf, "1.1", "1.2", "MFA on root", "PASS", "FAIL")
}

func TestSecretFindings(t *testing.T) {
	var buf bytes.Buffer
	SecretFindings(&buf, []cloud.SecretFinding{{
		Severity: cloud.SeverityHigh, Type: "aws_key", Provider: "aws",
		Resource: "lambda:fn", Key: "AWS_KEY",
	}})
	assertContains(t, &buf, "lambda:fn", "AWS_KEY")
}

func TestAuditReport(t *testing.T) {
	var buf bytes.Buffer
	AuditReport(&buf, &audit.Report{
		Duration: "1s",
		IAM:      []cloud.Finding{{Severity: cloud.SeverityCritical, Type: cloud.FindingAdminAccess, Provider: "aws", Principal: &cloud.Principal{Name: "x"}}},
		Storage:  []cloud.BucketFinding{{Severity: cloud.SeverityHigh, Provider: "aws", Bucket: "b"}},
		Summary: audit.ReportSummary{
			TotalFindings: 2, DomainsRun: 2,
			BySeverity: map[string]int{"CRITICAL": 1, "HIGH": 1},
		},
	})
	assertContains(t, &buf, "IAM", "STORAGE", "SUMMARY")
}

func TestInventoryResources(t *testing.T) {
	var buf bytes.Buffer
	now := time.Now()
	InventoryResources(&buf, []cloud.InventoryResource{
		{Type: "ec2:instance", ID: "i-1", Name: "web", Region: "us-east-1",
			Provider: "aws", Status: "running", CreatedAt: &now,
			Tags: map[string]string{"env": "prod"}},
	})
	assertContains(t, &buf, "ec2:instance", "web")
}

func TestQuotaUsages(t *testing.T) {
	var buf bytes.Buffer
	QuotaUsages(&buf, []cloud.QuotaUsage{
		{Provider: "aws", Service: "EC2", QuotaName: "EIPs", Used: 5, Limit: 5, Utilization: 100},
	})
	assertContains(t, &buf, "EIPs")
}

func TestFormatTags(t *testing.T) {
	got := formatTags(map[string]string{"env": "prod", "owner": "team"}, 100)
	if !strings.Contains(got, "env") || !strings.Contains(got, "prod") {
		t.Errorf("got %q", got)
	}
	if formatTags(nil, 100) != "" {
		t.Error("nil tags should return empty")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 100, "hello"},
		{"hello world", 5, "he..."},
		{"abc", 3, "abc"},
	}
	for _, tt := range tests {
		got := truncate(tt.in, tt.n)
		if got != tt.want {
			t.Errorf("truncate(%q, %d): got %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
}

func TestColorSeverity(t *testing.T) {
	// Just verify it doesn't panic for all severity levels
	for _, sev := range []cloud.Severity{
		cloud.SeverityCritical, cloud.SeverityHigh, cloud.SeverityMedium,
		cloud.SeverityLow, cloud.SeverityInfo, "unknown",
	} {
		_ = colorSeverity(sev)
	}
}
