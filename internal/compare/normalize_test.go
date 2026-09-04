package compare

import (
	"strings"
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
			name: "drift report",
			data: `{"results": [{"resource_type": "aws_security_group", "status": "MODIFIED"}], "total": 1}`,
			want: ReportTypeDrift,
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

func TestNormalizeReport_Drift(t *testing.T) {
	data := []byte(`{
		"results": [
			{
				"resource_type": "aws_security_group",
				"resource_id": "sg-123",
				"resource_name": "aws_security_group.web",
				"provider": "aws",
				"status": "MODIFIED",
				"fields": [{"field": "ingress.0.cidr_blocks", "expected": "10.0.0.0/8", "actual": "0.0.0.0/0"}]
			},
			{
				"resource_type": "aws_instance",
				"resource_id": "i-456",
				"resource_name": "aws_instance.app",
				"provider": "aws",
				"status": "DELETED"
			},
			{
				"resource_type": "aws_s3_bucket",
				"resource_name": "aws_s3_bucket.data",
				"provider": "aws",
				"status": "IN_SYNC"
			}
		],
		"total": 3
	}`)

	findings, err := NormalizeReport(data)
	if err != nil {
		t.Fatalf("NormalizeReport: %v", err)
	}
	// IN_SYNC is the absence of drift, not a finding.
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (IN_SYNC excluded)", len(findings))
	}

	byID := map[string]NormalizedFinding{}
	for _, f := range findings {
		if f.Domain != "drift" {
			t.Errorf("Domain = %q, want drift", f.Domain)
		}
		byID[f.ResourceID] = f
	}

	mod, ok := byID["aws_security_group.web"] // keys on the terraform address
	if !ok {
		t.Fatal("MODIFIED finding missing (should key on terraform address)")
	}
	if mod.Type != "MODIFIED" || mod.Severity != "MEDIUM" {
		t.Errorf("modified: Type=%q Severity=%q, want MODIFIED/MEDIUM", mod.Type, mod.Severity)
	}
	if !strings.Contains(mod.Detail, "ingress.0.cidr_blocks") {
		t.Errorf("modified Detail should summarize drifted fields, got %q", mod.Detail)
	}

	del, ok := byID["aws_instance.app"]
	if !ok {
		t.Fatal("DELETED finding missing")
	}
	if del.Severity != "HIGH" {
		t.Errorf("deleted severity = %q, want HIGH", del.Severity)
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

// A comparison is only as complete as its inputs, and this is what carries that
// from a saved report into the diff.
func TestReportIncomplete(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "an envelope that could not read part of the account",
			data: `{"findings":[],"total":0,"incomplete":["describe regions: AccessDenied; scanned us-east-1 only"]}`,
			want: []string{"describe regions: AccessDenied; scanned us-east-1 only"},
		},
		{
			name: "a whole scan reports nothing unread",
			data: `{"findings":[],"total":0,"incomplete":[]}`,
			want: nil,
		},
		{
			// The positive control on the two above: a reader that returned a
			// constant would pass both.
			name: "several entries are all carried",
			data: `{"resources":[],"incomplete":["a","b","c"]}`,
			want: []string{"a", "b", "c"},
		},
		{
			// An older report with no such key, and a file that is not a report
			// at all, are the same answer here — this cannot tell either from a
			// whole scan, which is why the caller labels the entries by side
			// rather than implying the inputs were complete.
			name: "a report predating the key",
			data: `{"findings":[],"total":0}`,
			want: nil,
		},
		{
			name: "not a report",
			data: `not json`,
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ReportIncomplete([]byte(tc.data))
			if len(got) != len(tc.want) {
				t.Fatalf("ReportIncomplete() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("entry %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
