package network

import (
	"context"
	"errors"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockNetworkProvider struct {
	name     string
	findings []cloud.NetworkFinding
	err      error
}

func (m *mockNetworkProvider) Name() string                   { return m.name }
func (m *mockNetworkProvider) Detect(_ context.Context) bool { return true }
func (m *mockNetworkProvider) AuditNetwork(_ context.Context) ([]cloud.NetworkFinding, error) {
	return m.findings, m.err
}

func TestScan(t *testing.T) {
	critical := cloud.NetworkFinding{Severity: cloud.SeverityCritical, Type: cloud.NetworkAdminPortOpen, Provider: "aws", Resource: "sg-001"}
	high := cloud.NetworkFinding{Severity: cloud.SeverityHigh, Type: cloud.NetworkOpenIngress, Provider: "aws", Resource: "sg-002"}
	medium := cloud.NetworkFinding{Severity: cloud.SeverityMedium, Type: cloud.NetworkOpenEgress, Provider: "aws", Resource: "sg-003"}

	tests := []struct {
		name          string
		providers     []cloud.NetworkProvider
		opts          ScanOptions
		wantResources []string
		wantErr       bool
	}{
		{
			name: "single provider returns all findings",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", findings: []cloud.NetworkFinding{high, critical}},
			},
			opts:          ScanOptions{},
			wantResources: []string{"sg-001", "sg-002"},
		},
		{
			name: "findings sorted by severity descending",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", findings: []cloud.NetworkFinding{medium, critical, high}},
			},
			opts:          ScanOptions{},
			wantResources: []string{"sg-001", "sg-002", "sg-003"},
		},
		{
			name: "severity filter excludes medium",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", findings: []cloud.NetworkFinding{critical, high, medium}},
			},
			opts:          ScanOptions{MinSeverity: cloud.SeverityHigh},
			wantResources: []string{"sg-001", "sg-002"},
		},
		{
			name: "severity filter keeps only critical",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", findings: []cloud.NetworkFinding{critical, high, medium}},
			},
			opts:          ScanOptions{MinSeverity: cloud.SeverityCritical},
			wantResources: []string{"sg-001"},
		},
		{
			name: "multiple providers merged and sorted",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", findings: []cloud.NetworkFinding{medium}},
				&mockNetworkProvider{name: "gcp", findings: []cloud.NetworkFinding{critical, high}},
			},
			opts:          ScanOptions{},
			wantResources: []string{"sg-001", "sg-002", "sg-003"},
		},
		{
			name: "same severity sorted by resource name",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", findings: []cloud.NetworkFinding{
					{Severity: cloud.SeverityHigh, Resource: "sg-zzz"},
					{Severity: cloud.SeverityHigh, Resource: "sg-aaa"},
				}},
			},
			opts:          ScanOptions{},
			wantResources: []string{"sg-aaa", "sg-zzz"},
		},
		{
			name: "empty provider returns empty result",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", findings: nil},
			},
			opts:          ScanOptions{},
			wantResources: []string{},
		},
		{
			name:          "no providers returns empty result",
			providers:     []cloud.NetworkProvider{},
			opts:          ScanOptions{},
			wantResources: []string{},
		},
		{
			name: "provider error is returned",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", err: errors.New("credentials expired")},
			},
			opts:    ScanOptions{},
			wantErr: true,
		},
		{
			name: "all findings filtered out by severity",
			providers: []cloud.NetworkProvider{
				&mockNetworkProvider{name: "aws", findings: []cloud.NetworkFinding{medium}},
			},
			opts:          ScanOptions{MinSeverity: cloud.SeverityCritical},
			wantResources: []string{},
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

			if len(got) != len(tt.wantResources) {
				t.Fatalf("got %d findings, want %d", len(got), len(tt.wantResources))
			}
			for i, res := range tt.wantResources {
				if got[i].Resource != res {
					t.Errorf("finding[%d]: got Resource %q, want %q", i, got[i].Resource, res)
				}
			}
		})
	}
}

func TestScanErrorWrapsProviderName(t *testing.T) {
	provider := &mockNetworkProvider{name: "mycloud", err: errors.New("auth failed")}
	_, err := Scan(context.Background(), []cloud.NetworkProvider{provider}, ScanOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	want := "mycloud: auth failed"
	if err.Error() != want {
		t.Errorf("error message: got %q, want %q", err.Error(), want)
	}
}
