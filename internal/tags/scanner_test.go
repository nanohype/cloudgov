package tags

import (
	"context"
	"errors"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockTagProvider struct {
	name     string
	findings []cloud.TagFinding
	err      error
}

func (m *mockTagProvider) Name() string                   { return m.name }
func (m *mockTagProvider) Detect(_ context.Context) bool { return true }
func (m *mockTagProvider) AuditTags(_ context.Context, _ []string) ([]cloud.TagFinding, error) {
	return m.findings, m.err
}

func TestScan(t *testing.T) {
	f1 := cloud.TagFinding{Severity: cloud.SeverityMedium, Provider: "aws", ResourceType: "ec2:instance", ResourceID: "i-001", MissingTags: []string{"owner"}}
	f2 := cloud.TagFinding{Severity: cloud.SeverityMedium, Provider: "aws", ResourceType: "s3:bucket", ResourceID: "my-bucket", MissingTags: []string{"env", "cost-center"}}
	f3 := cloud.TagFinding{Severity: cloud.SeverityMedium, Provider: "gcp", ResourceType: "compute:instance", ResourceID: "vm-001", MissingTags: []string{"env"}}

	tests := []struct {
		name        string
		providers   []cloud.TagProvider
		opts        ScanOptions
		wantCount   int
		wantErr     bool
	}{
		{
			name: "single provider returns all findings",
			providers: []cloud.TagProvider{
				&mockTagProvider{name: "aws", findings: []cloud.TagFinding{f1, f2}},
			},
			opts:      ScanOptions{Required: []string{"owner", "env", "cost-center"}},
			wantCount: 2,
		},
		{
			name: "multiple providers merged",
			providers: []cloud.TagProvider{
				&mockTagProvider{name: "aws", findings: []cloud.TagFinding{f1, f2}},
				&mockTagProvider{name: "gcp", findings: []cloud.TagFinding{f3}},
			},
			opts:      ScanOptions{Required: []string{"owner", "env"}},
			wantCount: 3,
		},
		{
			name: "severity filter excludes findings below threshold",
			providers: []cloud.TagProvider{
				&mockTagProvider{name: "aws", findings: []cloud.TagFinding{f1}},
			},
			opts:      ScanOptions{MinSeverity: cloud.SeverityHigh},
			wantCount: 0,
		},
		{
			name: "medium severity included at medium threshold",
			providers: []cloud.TagProvider{
				&mockTagProvider{name: "aws", findings: []cloud.TagFinding{f1, f2}},
			},
			opts:      ScanOptions{MinSeverity: cloud.SeverityMedium},
			wantCount: 2,
		},
		{
			name: "no providers returns empty result",
			providers: []cloud.TagProvider{},
			opts:      ScanOptions{},
			wantCount: 0,
		},
		{
			name: "empty provider returns empty result",
			providers: []cloud.TagProvider{
				&mockTagProvider{name: "aws", findings: nil},
			},
			opts:      ScanOptions{},
			wantCount: 0,
		},
		{
			name: "provider error is returned",
			providers: []cloud.TagProvider{
				&mockTagProvider{name: "aws", err: errors.New("credentials expired")},
			},
			opts:    ScanOptions{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Scan(context.Background(), tt.providers, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != tt.wantCount {
				t.Fatalf("got %d findings, want %d", len(got), tt.wantCount)
			}
		})
	}
}

func TestScanErrorWrapsProviderName(t *testing.T) {
	provider := &mockTagProvider{name: "mycloud", err: errors.New("auth failed")}
	_, err := Scan(context.Background(), []cloud.TagProvider{provider}, ScanOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	want := "mycloud: auth failed"
	if err.Error() != want {
		t.Errorf("error message: got %q, want %q", err.Error(), want)
	}
}

func TestScanSortsByProviderThenTypeTheniID(t *testing.T) {
	findings := []cloud.TagFinding{
		{Severity: cloud.SeverityMedium, Provider: "gcp", ResourceType: "compute:instance", ResourceID: "z"},
		{Severity: cloud.SeverityMedium, Provider: "aws", ResourceType: "s3:bucket", ResourceID: "b"},
		{Severity: cloud.SeverityMedium, Provider: "aws", ResourceType: "ec2:instance", ResourceID: "a"},
	}
	provider := &mockTagProvider{name: "multi", findings: findings}

	got, err := Scan(context.Background(), []cloud.TagProvider{provider}, ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3", len(got))
	}
	// Sorted by provider first: aws before gcp
	if got[0].Provider != "aws" || got[2].Provider != "gcp" {
		t.Errorf("not sorted by provider: got [%s, %s, %s]", got[0].Provider, got[1].Provider, got[2].Provider)
	}
}
