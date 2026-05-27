package quota

import (
	"context"
	"errors"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockQuotaProvider struct {
	name   string
	quotas []cloud.QuotaUsage
	err    error
}

func (m *mockQuotaProvider) Name() string                  { return m.name }
func (m *mockQuotaProvider) Detect(_ context.Context) bool { return true }
func (m *mockQuotaProvider) ListQuotas(_ context.Context) ([]cloud.QuotaUsage, error) {
	return m.quotas, m.err
}

func TestScan(t *testing.T) {
	high := cloud.QuotaUsage{Provider: "aws", Service: "EC2", QuotaName: "Instances", Used: 95, Limit: 100, Utilization: 95.0, Region: "us-east-1"}
	medium := cloud.QuotaUsage{Provider: "aws", Service: "IAM", QuotaName: "Roles", Used: 600, Limit: 1000, Utilization: 60.0, Region: "global"}
	low := cloud.QuotaUsage{Provider: "gcp", Service: "Compute", QuotaName: "CPUs", Used: 10, Limit: 100, Utilization: 10.0, Region: "us-central1"}

	tests := []struct {
		name      string
		providers []cloud.QuotaProvider
		opts      ScanOptions
		wantNames []string
		wantErr   bool
	}{
		{
			name: "single provider sorted by utilization desc",
			providers: []cloud.QuotaProvider{
				&mockQuotaProvider{name: "aws", quotas: []cloud.QuotaUsage{medium, high}},
			},
			opts:      ScanOptions{},
			wantNames: []string{"Instances", "Roles"},
		},
		{
			name: "multiple providers merged and sorted",
			providers: []cloud.QuotaProvider{
				&mockQuotaProvider{name: "aws", quotas: []cloud.QuotaUsage{high, medium}},
				&mockQuotaProvider{name: "gcp", quotas: []cloud.QuotaUsage{low}},
			},
			opts:      ScanOptions{},
			wantNames: []string{"Instances", "Roles", "CPUs"},
		},
		{
			name: "threshold filters low utilization",
			providers: []cloud.QuotaProvider{
				&mockQuotaProvider{name: "aws", quotas: []cloud.QuotaUsage{high, medium, low}},
			},
			opts:      ScanOptions{MinUtilization: 50.0},
			wantNames: []string{"Instances", "Roles"},
		},
		{
			name: "threshold at exact boundary includes",
			providers: []cloud.QuotaProvider{
				&mockQuotaProvider{name: "aws", quotas: []cloud.QuotaUsage{medium}},
			},
			opts:      ScanOptions{MinUtilization: 60.0},
			wantNames: []string{"Roles"},
		},
		{
			name:      "empty provider returns empty",
			providers: []cloud.QuotaProvider{&mockQuotaProvider{name: "aws", quotas: nil}},
			opts:      ScanOptions{},
			wantNames: []string{},
		},
		{
			name:      "no providers returns empty",
			providers: []cloud.QuotaProvider{},
			opts:      ScanOptions{},
			wantNames: []string{},
		},
		{
			name:      "provider error is returned",
			providers: []cloud.QuotaProvider{&mockQuotaProvider{name: "aws", err: errors.New("access denied")}},
			opts:      ScanOptions{},
			wantErr:   true,
		},
		{
			name: "error from second provider is returned",
			providers: []cloud.QuotaProvider{
				&mockQuotaProvider{name: "aws", quotas: []cloud.QuotaUsage{high}},
				&mockQuotaProvider{name: "gcp", err: errors.New("quota exceeded")},
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

			if len(got) != len(tt.wantNames) {
				t.Fatalf("got %d quotas, want %d", len(got), len(tt.wantNames))
			}
			for i, name := range tt.wantNames {
				if got[i].QuotaName != name {
					t.Errorf("quota[%d]: got QuotaName %q, want %q", i, got[i].QuotaName, name)
				}
			}

			for i := 1; i < len(got); i++ {
				if got[i].Utilization > got[i-1].Utilization {
					t.Errorf("quotas not sorted: [%d].Utilization=%f > [%d].Utilization=%f",
						i, got[i].Utilization, i-1, got[i-1].Utilization)
				}
			}
		})
	}
}

func TestScanErrorWrapsProviderName(t *testing.T) {
	provider := &mockQuotaProvider{name: "mycloud", err: errors.New("auth failed")}
	_, err := Scan(context.Background(), []cloud.QuotaProvider{provider}, ScanOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	want := "mycloud: auth failed"
	if err.Error() != want {
		t.Errorf("error message: got %q, want %q", err.Error(), want)
	}
}

func TestSummarize(t *testing.T) {
	tests := []struct {
		name   string
		quotas []cloud.QuotaUsage
		want   Summary
	}{
		{
			name:   "nil slice",
			quotas: nil,
			want:   Summary{},
		},
		{
			name:   "empty slice",
			quotas: []cloud.QuotaUsage{},
			want:   Summary{},
		},
		{
			name: "mixed severities",
			quotas: []cloud.QuotaUsage{
				{Utilization: 95.0}, // critical
				{Utilization: 85.0}, // high
				{Utilization: 60.0}, // medium
				{Utilization: 30.0}, // low
				{Utilization: 92.0}, // critical
			},
			want: Summary{Total: 5, Critical: 2, High: 1, Medium: 1, Low: 1},
		},
		{
			name: "all critical",
			quotas: []cloud.QuotaUsage{
				{Utilization: 100.0},
				{Utilization: 90.0},
			},
			want: Summary{Total: 2, Critical: 2},
		},
		{
			name: "boundary values",
			quotas: []cloud.QuotaUsage{
				{Utilization: 90.0},  // critical (>= 90)
				{Utilization: 89.9},  // high
				{Utilization: 80.0},  // high (>= 80)
				{Utilization: 79.9},  // medium
				{Utilization: 50.0},  // medium (>= 50)
				{Utilization: 49.9},  // low
			},
			want: Summary{Total: 6, Critical: 1, High: 2, Medium: 2, Low: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Summarize(tt.quotas)
			if got != tt.want {
				t.Errorf("Summarize() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
