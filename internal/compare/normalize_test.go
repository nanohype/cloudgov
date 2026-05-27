package compare

import (
	"testing"
)

func TestDetectType(t *testing.T) {
	tests := []struct {
		name string
		data string
		want ReportType
	}{
		{
			name: "audit report",
			data: `{"summary": {"total_findings": 5}, "duration": "1.5s", "iam": [], "storage": []}`,
			want: ReportTypeAudit,
		},
		{
			name: "cost report",
			data: `{"diffs": [{"provider": "aws"}]}`,
			want: ReportTypeCost,
		},
		{
			name: "iam report",
			data: `{"findings": [{"severity": "HIGH"}], "total": 1, "principals_scanned": 5}`,
			want: ReportTypeIAM,
		},
		{
			name: "orphans report",
			data: `{"resources": [{"kind": "disk"}], "total": 1, "estimated_monthly_usd": 10.0}`,
			want: ReportTypeOrphans,
		},
		{
			name: "storage report",
			data: `{"findings": [{"bucket": "my-bucket", "type": "PUBLIC_ACCESS"}], "total": 1}`,
			want: ReportTypeStorage,
		},
		{
			name: "network report",
			data: `{"findings": [{"protocol": "tcp", "port": "22", "resource": "sg-1"}], "total": 1}`,
			want: ReportTypeNetwork,
		},
		{
			name: "certs report",
			data: `{"findings": [{"expires_at": "2024-01-01T00:00:00Z", "days_left": 30}], "total": 1}`,
			want: ReportTypeCerts,
		},
		{
			name: "tags report",
			data: `{"findings": [{"missing_tags": ["env"], "resource_id": "i-123"}], "total": 1}`,
			want: ReportTypeTags,
		},
		{
			name: "secrets report",
			data: `{"findings": [{"match": "AKIA****", "key": "AWS_ACCESS_KEY_ID"}], "total": 1}`,
			want: ReportTypeSecrets,
		},
		{
			name: "quotas report",
			data: `{"quotas": [{"provider": "aws"}], "total": 1}`,
			want: ReportTypeQuotas,
		},
		{
			name: "unknown report",
			data: `{"foo": "bar"}`,
			want: ReportTypeUnknown,
		},
		{
			name: "invalid JSON",
			data: `not json`,
			want: ReportTypeUnknown,
		},
		{
			name: "empty findings",
			data: `{"findings": [], "total": 0}`,
			want: ReportTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectType([]byte(tt.data))
			if got != tt.want {
				t.Errorf("DetectType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeReport_IAM(t *testing.T) {
	data := []byte(`{
		"findings": [
			{
				"severity": "HIGH",
				"type": "ADMIN_ACCESS",
				"provider": "aws",
				"resource": "arn:aws:iam::123:role/admin",
				"detail": "has admin access"
			}
		],
		"total": 1,
		"principals_scanned": 5
	}`)

	findings, err := NormalizeReport(data)
	if err != nil {
		t.Fatalf("NormalizeReport: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Domain != "iam" {
		t.Errorf("Domain = %q, want iam", f.Domain)
	}
	if f.Type != "ADMIN_ACCESS" {
		t.Errorf("Type = %q, want ADMIN_ACCESS", f.Type)
	}
}

func TestNormalizeReport_Storage(t *testing.T) {
	data := []byte(`{
		"findings": [
			{
				"severity": "HIGH",
				"type": "PUBLIC_ACCESS",
				"provider": "aws",
				"bucket": "my-bucket",
				"detail": "bucket is public"
			}
		],
		"total": 1
	}`)

	findings, err := NormalizeReport(data)
	if err != nil {
		t.Fatalf("NormalizeReport: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Domain != "storage" {
		t.Errorf("Domain = %q, want storage", f.Domain)
	}
	if f.ResourceID != "my-bucket" {
		t.Errorf("ResourceID = %q, want my-bucket", f.ResourceID)
	}
}

func TestNormalizeReport_Orphans(t *testing.T) {
	data := []byte(`{
		"resources": [
			{
				"Kind": "disk",
				"ID": "vol-123",
				"Name": "test-vol",
				"Provider": "aws",
				"MonthlyCost": 10.0,
				"Detail": "100 GiB available"
			}
		],
		"total": 1,
		"estimated_monthly_usd": 10.0
	}`)

	findings, err := NormalizeReport(data)
	if err != nil {
		t.Fatalf("NormalizeReport: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Domain != "orphans" {
		t.Errorf("Domain = %q, want orphans", f.Domain)
	}
	if f.ResourceID != "vol-123" {
		t.Errorf("ResourceID = %q, want vol-123", f.ResourceID)
	}
}

func TestNormalizeReport_CostError(t *testing.T) {
	data := []byte(`{"diffs": []}`)
	_, err := NormalizeReport(data)
	if err == nil {
		t.Fatal("expected error for cost report")
	}
}

func TestNormalizeReport_UnknownError(t *testing.T) {
	data := []byte(`{"foo": "bar"}`)
	_, err := NormalizeReport(data)
	if err == nil {
		t.Fatal("expected error for unknown report")
	}
}

func TestNormalizeReport_Audit(t *testing.T) {
	data := []byte(`{
		"summary": {"total_findings": 2},
		"duration": "1s",
		"iam": [
			{"severity": "HIGH", "type": "ADMIN_ACCESS", "provider": "aws", "resource": "role/admin", "detail": "admin"}
		],
		"storage": [
			{"severity": "HIGH", "type": "PUBLIC_ACCESS", "provider": "aws", "bucket": "pub-bucket", "detail": "public"}
		]
	}`)

	findings, err := NormalizeReport(data)
	if err != nil {
		t.Fatalf("NormalizeReport: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	domains := map[string]bool{}
	for _, f := range findings {
		domains[f.Domain] = true
	}
	if !domains["iam"] || !domains["storage"] {
		t.Errorf("expected iam and storage domains, got %v", domains)
	}
}

func TestMatchKey_ExcludesSeverity(t *testing.T) {
	f1 := NormalizedFinding{Provider: "aws", Type: "ADMIN_ACCESS", ResourceID: "role/admin", Detail: "admin", Severity: "HIGH"}
	f2 := NormalizedFinding{Provider: "aws", Type: "ADMIN_ACCESS", ResourceID: "role/admin", Detail: "admin", Severity: "CRITICAL"}

	if f1.MatchKey() != f2.MatchKey() {
		t.Errorf("MatchKey should ignore severity: %q != %q", f1.MatchKey(), f2.MatchKey())
	}
}
