package certs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockCertProvider struct {
	name     string
	findings []cloud.CertFinding
	err      error
}

func (m *mockCertProvider) Name() string                   { return m.name }
func (m *mockCertProvider) Detect(_ context.Context) bool { return true }
func (m *mockCertProvider) ListCertificates(_ context.Context) ([]cloud.CertFinding, error) {
	return m.findings, m.err
}

func TestScan(t *testing.T) {
	now := time.Now()
	expired := cloud.CertFinding{Severity: cloud.SeverityCritical, Status: cloud.CertExpired, Provider: "aws", Domain: "expired.example.com", DaysLeft: -5, ExpiresAt: now.AddDate(0, 0, -5)}
	week := cloud.CertFinding{Severity: cloud.SeverityCritical, Status: cloud.CertCritical, Provider: "aws", Domain: "week.example.com", DaysLeft: 5, ExpiresAt: now.AddDate(0, 0, 5)}
	month := cloud.CertFinding{Severity: cloud.SeverityHigh, Status: cloud.CertHigh, Provider: "aws", Domain: "month.example.com", DaysLeft: 20, ExpiresAt: now.AddDate(0, 0, 20)}
	sixtydays := cloud.CertFinding{Severity: cloud.SeverityMedium, Status: cloud.CertMedium, Provider: "aws", Domain: "sixty.example.com", DaysLeft: 50, ExpiresAt: now.AddDate(0, 0, 50)}
	ninetydays := cloud.CertFinding{Severity: cloud.SeverityLow, Status: cloud.CertLow, Provider: "aws", Domain: "ninety.example.com", DaysLeft: 80, ExpiresAt: now.AddDate(0, 0, 80)}

	tests := []struct {
		name        string
		providers   []cloud.CertProvider
		opts        ScanOptions
		wantDomains []string
		wantErr     bool
	}{
		{
			name: "single provider returns all findings",
			providers: []cloud.CertProvider{
				&mockCertProvider{name: "aws", findings: []cloud.CertFinding{expired, week}},
			},
			opts:        ScanOptions{},
			wantDomains: []string{"expired.example.com", "week.example.com"},
		},
		{
			name: "findings sorted by days left ascending",
			providers: []cloud.CertProvider{
				&mockCertProvider{name: "aws", findings: []cloud.CertFinding{ninetydays, month, expired, week, sixtydays}},
			},
			opts:        ScanOptions{},
			wantDomains: []string{"expired.example.com", "week.example.com", "month.example.com", "sixty.example.com", "ninety.example.com"},
		},
		{
			name: "days filter excludes certs beyond threshold",
			providers: []cloud.CertProvider{
				&mockCertProvider{name: "aws", findings: []cloud.CertFinding{expired, week, month, sixtydays, ninetydays}},
			},
			opts:        ScanOptions{Days: 30},
			wantDomains: []string{"expired.example.com", "week.example.com", "month.example.com"},
		},
		{
			name: "expired certs always included regardless of days filter",
			providers: []cloud.CertProvider{
				&mockCertProvider{name: "aws", findings: []cloud.CertFinding{expired, ninetydays}},
			},
			opts:        ScanOptions{Days: 7},
			wantDomains: []string{"expired.example.com"},
		},
		{
			name: "severity filter excludes low findings",
			providers: []cloud.CertProvider{
				&mockCertProvider{name: "aws", findings: []cloud.CertFinding{expired, week, month, ninetydays}},
			},
			opts:        ScanOptions{MinSeverity: cloud.SeverityHigh},
			wantDomains: []string{"expired.example.com", "week.example.com", "month.example.com"},
		},
		{
			name: "multiple providers merged and sorted",
			providers: []cloud.CertProvider{
				&mockCertProvider{name: "aws", findings: []cloud.CertFinding{month}},
				&mockCertProvider{name: "gcp", findings: []cloud.CertFinding{expired, week}},
			},
			opts:        ScanOptions{},
			wantDomains: []string{"expired.example.com", "week.example.com", "month.example.com"},
		},
		{
			name: "no providers returns empty result",
			providers: []cloud.CertProvider{},
			opts:        ScanOptions{},
			wantDomains: []string{},
		},
		{
			name: "provider error is returned",
			providers: []cloud.CertProvider{
				&mockCertProvider{name: "aws", err: errors.New("credentials expired")},
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

			if len(got) != len(tt.wantDomains) {
				t.Fatalf("got %d findings, want %d", len(got), len(tt.wantDomains))
			}
			for i, domain := range tt.wantDomains {
				if got[i].Domain != domain {
					t.Errorf("finding[%d]: got Domain %q, want %q", i, got[i].Domain, domain)
				}
			}
		})
	}
}

func TestScanErrorWrapsProviderName(t *testing.T) {
	provider := &mockCertProvider{name: "mycloud", err: errors.New("auth failed")}
	_, err := Scan(context.Background(), []cloud.CertProvider{provider}, ScanOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	want := "mycloud: auth failed"
	if err.Error() != want {
		t.Errorf("error message: got %q, want %q", err.Error(), want)
	}
}
