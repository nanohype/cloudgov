package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// roundTrip encodes via fn into a buffer, then decodes into T.
func roundTrip[T any](t *testing.T, fn func(*bytes.Buffer) error) T {
	t.Helper()
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		t.Fatalf("write error: %v", err)
	}
	var out T
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal error: %v (json: %s)", err, buf.String())
	}
	return out
}

func TestWriteIAM(t *testing.T) {
	findings := []cloud.Finding{
		{
			Severity:    cloud.SeverityCritical,
			Type:        cloud.FindingAdminAccess,
			Provider:    "aws",
			Principal:   &cloud.Principal{ID: "p1", Name: "admin-role", Type: cloud.PrincipalRole, Provider: "aws"},
			Resource:    "arn:aws:iam:::role/admin-role",
			Detail:      "has admin access",
			Remediation: "restrict permissions",
		},
		{
			Severity:    cloud.SeverityHigh,
			Type:        cloud.FindingUnusedPermission,
			Provider:    "aws",
			Principal:   &cloud.Principal{ID: "p2", Name: "dev-user", Type: cloud.PrincipalUser, Provider: "aws"},
			Resource:    "arn:aws:s3:::*",
			Detail:      "permission never used",
			Remediation: "remove unused permission",
		},
		{
			Severity:  cloud.SeverityLow,
			Type:      cloud.FindingWildcardResource,
			Provider:  "gcp",
			Principal: nil,
			Resource:  "*",
			Detail:    "wildcard resource",
		},
	}

	type iamOut struct {
		Findings   []json.RawMessage `json:"findings"`
		Total      int               `json:"total"`
		Principals int               `json:"principals_scanned"`
	}

	out := roundTrip[iamOut](t, func(buf *bytes.Buffer) error {
		return WriteIAM(buf, findings, 5, nil)
	})

	if out.Total != len(findings) {
		t.Errorf("total: got %d, want %d", out.Total, len(findings))
	}
	if out.Principals != 5 {
		t.Errorf("principals_scanned: got %d, want 5", out.Principals)
	}
	if len(out.Findings) != len(findings) {
		t.Errorf("findings length: got %d, want %d", len(out.Findings), len(findings))
	}

	tests := []struct {
		idx      int
		severity string
		typ      string
		provider string
	}{
		{0, "CRITICAL", "ADMIN_ACCESS", "aws"},
		{1, "HIGH", "UNUSED_PERMISSION", "aws"},
		{2, "LOW", "WILDCARD_RESOURCE", "gcp"},
	}
	for _, tc := range tests {
		var f map[string]interface{}
		if err := json.Unmarshal(out.Findings[tc.idx], &f); err != nil {
			t.Fatalf("finding[%d] unmarshal: %v", tc.idx, err)
		}
		if got := f["Severity"]; got != tc.severity {
			t.Errorf("finding[%d].Severity: got %v, want %s", tc.idx, got, tc.severity)
		}
		if got := f["Type"]; got != tc.typ {
			t.Errorf("finding[%d].Type: got %v, want %s", tc.idx, got, tc.typ)
		}
		if got := f["Provider"]; got != tc.provider {
			t.Errorf("finding[%d].Provider: got %v, want %s", tc.idx, got, tc.provider)
		}
	}
}

func TestWriteIAMEmpty(t *testing.T) {
	type iamOut struct {
		Findings   []json.RawMessage `json:"findings"`
		Total      int               `json:"total"`
		Principals int               `json:"principals_scanned"`
	}
	out := roundTrip[iamOut](t, func(buf *bytes.Buffer) error {
		return WriteIAM(buf, nil, 0, nil)
	})
	if out.Total != 0 {
		t.Errorf("total: got %d, want 0", out.Total)
	}
	if out.Principals != 0 {
		t.Errorf("principals_scanned: got %d, want 0", out.Principals)
	}
}

func TestWriteIAMPrincipalNil(t *testing.T) {
	findings := []cloud.Finding{
		{Severity: cloud.SeverityInfo, Type: cloud.FindingBroadScope, Provider: "azure", Principal: nil, Resource: "/subscriptions/*"},
	}
	type iamOut struct {
		Findings []json.RawMessage `json:"findings"`
		Total    int               `json:"total"`
	}
	out := roundTrip[iamOut](t, func(buf *bytes.Buffer) error {
		return WriteIAM(buf, findings, 1, nil)
	})
	if out.Total != 1 {
		t.Errorf("total: got %d, want 1", out.Total)
	}
	var f map[string]interface{}
	if err := json.Unmarshal(out.Findings[0], &f); err != nil {
		t.Fatalf("unmarshal finding: %v", err)
	}
	if principal, ok := f["Principal"]; ok && principal != nil {
		t.Errorf("Principal should be nil, got %v", principal)
	}
}

func TestWriteStorage(t *testing.T) {
	findings := []cloud.BucketFinding{
		{
			Severity:    cloud.SeverityCritical,
			Type:        cloud.BucketPublicAccess,
			Provider:    "aws",
			Bucket:      "my-public-bucket",
			Region:      "us-east-1",
			Detail:      "bucket is publicly accessible",
			Remediation: "enable block public access",
		},
		{
			Severity: cloud.SeverityHigh,
			Type:     cloud.BucketUnencrypted,
			Provider: "gcp",
			Bucket:   "unencrypted-data",
			Region:   "us-central1",
			Detail:   "bucket has no encryption",
		},
		{
			Severity: cloud.SeverityMedium,
			Type:     cloud.BucketNoVersioning,
			Provider: "azure",
			Bucket:   "no-version-container",
			Region:   "eastus",
		},
	}

	type storageOut struct {
		Findings []json.RawMessage `json:"findings"`
		Total    int               `json:"total"`
	}

	out := roundTrip[storageOut](t, func(buf *bytes.Buffer) error {
		return WriteStorage(buf, findings)
	})

	if out.Total != len(findings) {
		t.Errorf("total: got %d, want %d", out.Total, len(findings))
	}
	if len(out.Findings) != len(findings) {
		t.Errorf("findings length: got %d, want %d", len(out.Findings), len(findings))
	}

	tests := []struct {
		idx    int
		bucket string
		typ    string
	}{
		{0, "my-public-bucket", "PUBLIC_ACCESS"},
		{1, "unencrypted-data", "UNENCRYPTED"},
		{2, "no-version-container", "NO_VERSIONING"},
	}
	for _, tc := range tests {
		var f map[string]interface{}
		if err := json.Unmarshal(out.Findings[tc.idx], &f); err != nil {
			t.Fatalf("finding[%d] unmarshal: %v", tc.idx, err)
		}
		if got := f["Bucket"]; got != tc.bucket {
			t.Errorf("finding[%d].Bucket: got %v, want %s", tc.idx, got, tc.bucket)
		}
		if got := f["Type"]; got != tc.typ {
			t.Errorf("finding[%d].Type: got %v, want %s", tc.idx, got, tc.typ)
		}
	}
}

func TestWriteStorageEmpty(t *testing.T) {
	type storageOut struct {
		Findings []json.RawMessage `json:"findings"`
		Total    int               `json:"total"`
	}
	out := roundTrip[storageOut](t, func(buf *bytes.Buffer) error {
		return WriteStorage(buf, nil)
	})
	if out.Total != 0 {
		t.Errorf("total: got %d, want 0", out.Total)
	}
}

func TestWriteOrphans(t *testing.T) {
	orphans := []cloud.OrphanResource{
		{Kind: cloud.OrphanDisk, ID: "vol-abc", Name: "old-disk", Region: "us-east-1", Provider: "aws", MonthlyCost: 12.50, Detail: "unattached"},
		{Kind: cloud.OrphanIP, ID: "eip-xyz", Name: "unused-eip", Region: "us-west-2", Provider: "aws", MonthlyCost: 3.60},
		{Kind: cloud.OrphanLoadBalancer, ID: "lb-123", Name: "stale-lb", Region: "eu-west-1", Provider: "aws", MonthlyCost: 20.00},
	}

	type resourceItem struct {
		Kind        string  `json:"Kind"`
		ID          string  `json:"ID"`
		MonthlyCost float64 `json:"MonthlyCost"`
	}
	type orphansOut struct {
		Resources           []resourceItem `json:"resources"`
		Total               int            `json:"total"`
		EstimatedMonthlyUSD float64        `json:"estimated_monthly_usd"`
	}

	out := roundTrip[orphansOut](t, func(buf *bytes.Buffer) error {
		return WriteOrphans(buf, orphans)
	})

	if out.Total != len(orphans) {
		t.Errorf("total: got %d, want %d", out.Total, len(orphans))
	}

	wantCost := 12.50 + 3.60 + 20.00
	if out.EstimatedMonthlyUSD != wantCost {
		t.Errorf("estimated_monthly_usd: got %f, want %f", out.EstimatedMonthlyUSD, wantCost)
	}

	if len(out.Resources) != len(orphans) {
		t.Errorf("resources length: got %d, want %d", len(out.Resources), len(orphans))
	}

	if out.Resources[0].Kind != "disk" {
		t.Errorf("resources[0].Kind: got %s, want disk", out.Resources[0].Kind)
	}
	if out.Resources[1].Kind != "ip" {
		t.Errorf("resources[1].Kind: got %s, want ip", out.Resources[1].Kind)
	}
	if out.Resources[2].Kind != "load_balancer" {
		t.Errorf("resources[2].Kind: got %s, want load_balancer", out.Resources[2].Kind)
	}
}

func TestWriteOrphansEmpty(t *testing.T) {
	type orphansOut struct {
		Resources           []json.RawMessage `json:"resources"`
		Total               int               `json:"total"`
		EstimatedMonthlyUSD float64           `json:"estimated_monthly_usd"`
	}
	out := roundTrip[orphansOut](t, func(buf *bytes.Buffer) error {
		return WriteOrphans(buf, nil)
	})
	if out.Total != 0 {
		t.Errorf("total: got %d, want 0", out.Total)
	}
	if out.EstimatedMonthlyUSD != 0 {
		t.Errorf("estimated_monthly_usd: got %f, want 0", out.EstimatedMonthlyUSD)
	}
}

func TestWriteOrphansMonthlyCostSum(t *testing.T) {
	orphans := []cloud.OrphanResource{
		{Kind: cloud.OrphanSnapshot, ID: "snap-1", MonthlyCost: 0},
		{Kind: cloud.OrphanImage, ID: "ami-1", MonthlyCost: 0},
	}
	type orphansOut struct {
		EstimatedMonthlyUSD float64 `json:"estimated_monthly_usd"`
		Total               int     `json:"total"`
	}
	out := roundTrip[orphansOut](t, func(buf *bytes.Buffer) error {
		return WriteOrphans(buf, orphans)
	})
	if out.EstimatedMonthlyUSD != 0 {
		t.Errorf("estimated_monthly_usd: got %f, want 0", out.EstimatedMonthlyUSD)
	}
	if out.Total != 2 {
		t.Errorf("total: got %d, want 2", out.Total)
	}
}

func TestWriteCost(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	diffs := []cloud.CostDiff{
		{
			Provider:    "aws",
			BeforeStart: now,
			BeforeEnd:   now.AddDate(0, 1, 0),
			AfterStart:  now.AddDate(0, 1, 0),
			AfterEnd:    now.AddDate(0, 2, 0),
			Entries: []cloud.CostDiffEntry{
				{Service: "EC2", Before: 100.0, After: 120.0, Delta: 20.0, PctChange: 20.0},
				{Service: "S3", Before: 50.0, After: 45.0, Delta: -5.0, PctChange: -10.0},
			},
			TotalBefore: 150.0,
			TotalAfter:  165.0,
			TotalDelta:  15.0,
		},
	}

	type entryItem struct {
		Service   string  `json:"Service"`
		Before    float64 `json:"Before"`
		After     float64 `json:"After"`
		Delta     float64 `json:"Delta"`
		PctChange float64 `json:"PctChange"`
	}
	type diffItem struct {
		Provider    string      `json:"Provider"`
		Entries     []entryItem `json:"Entries"`
		TotalBefore float64     `json:"TotalBefore"`
		TotalAfter  float64     `json:"TotalAfter"`
		TotalDelta  float64     `json:"TotalDelta"`
	}
	type costOut struct {
		Diffs []diffItem `json:"diffs"`
	}

	out := roundTrip[costOut](t, func(buf *bytes.Buffer) error {
		return WriteCost(buf, diffs)
	})

	if len(out.Diffs) != 1 {
		t.Fatalf("diffs length: got %d, want 1", len(out.Diffs))
	}

	d := out.Diffs[0]
	if d.Provider != "aws" {
		t.Errorf("Provider: got %s, want aws", d.Provider)
	}
	if d.TotalBefore != 150.0 {
		t.Errorf("TotalBefore: got %f, want 150.0", d.TotalBefore)
	}
	if d.TotalAfter != 165.0 {
		t.Errorf("TotalAfter: got %f, want 165.0", d.TotalAfter)
	}
	if d.TotalDelta != 15.0 {
		t.Errorf("TotalDelta: got %f, want 15.0", d.TotalDelta)
	}
	if len(d.Entries) != 2 {
		t.Fatalf("entries length: got %d, want 2", len(d.Entries))
	}
	if d.Entries[0].Service != "EC2" {
		t.Errorf("entries[0].Service: got %s, want EC2", d.Entries[0].Service)
	}
	if d.Entries[0].PctChange != 20.0 {
		t.Errorf("entries[0].PctChange: got %f, want 20.0", d.Entries[0].PctChange)
	}
	if d.Entries[1].Service != "S3" {
		t.Errorf("entries[1].Service: got %s, want S3", d.Entries[1].Service)
	}
	if d.Entries[1].Delta != -5.0 {
		t.Errorf("entries[1].Delta: got %f, want -5.0", d.Entries[1].Delta)
	}
}

func TestWriteCostEmpty(t *testing.T) {
	type costOut struct {
		Diffs []json.RawMessage `json:"diffs"`
	}
	out := roundTrip[costOut](t, func(buf *bytes.Buffer) error {
		return WriteCost(buf, nil)
	})
	if len(out.Diffs) != 0 {
		t.Errorf("diffs length: got %d, want 0", len(out.Diffs))
	}
}

func TestWriteCostMultipleProviders(t *testing.T) {
	diffs := []cloud.CostDiff{
		{Provider: "aws", TotalBefore: 200, TotalAfter: 210, TotalDelta: 10},
		{Provider: "gcp", TotalBefore: 80, TotalAfter: 75, TotalDelta: -5},
		{Provider: "azure", TotalBefore: 50, TotalAfter: 50, TotalDelta: 0},
	}

	type diffItem struct {
		Provider   string  `json:"Provider"`
		TotalDelta float64 `json:"TotalDelta"`
	}
	type costOut struct {
		Diffs []diffItem `json:"diffs"`
	}

	out := roundTrip[costOut](t, func(buf *bytes.Buffer) error {
		return WriteCost(buf, diffs)
	})

	if len(out.Diffs) != 3 {
		t.Fatalf("diffs length: got %d, want 3", len(out.Diffs))
	}
	providers := []string{"aws", "gcp", "azure"}
	deltas := []float64{10, -5, 0}
	for i, d := range out.Diffs {
		if d.Provider != providers[i] {
			t.Errorf("diffs[%d].Provider: got %s, want %s", i, d.Provider, providers[i])
		}
		if d.TotalDelta != deltas[i] {
			t.Errorf("diffs[%d].TotalDelta: got %f, want %f", i, d.TotalDelta, deltas[i])
		}
	}
}
