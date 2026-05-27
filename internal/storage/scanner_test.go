package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockStorageProvider struct {
	name     string
	findings []cloud.BucketFinding
	err      error
}

func (m *mockStorageProvider) Name() string                   { return m.name }
func (m *mockStorageProvider) Detect(_ context.Context) bool { return true }
func (m *mockStorageProvider) AuditStorage(_ context.Context) ([]cloud.BucketFinding, error) {
	return m.findings, m.err
}

func TestScan(t *testing.T) {
	critical := cloud.BucketFinding{Severity: cloud.SeverityCritical, Type: cloud.BucketPublicAccess, Provider: "aws", Bucket: "public-bucket"}
	high := cloud.BucketFinding{Severity: cloud.SeverityHigh, Type: cloud.BucketUnencrypted, Provider: "aws", Bucket: "unenc-bucket"}
	medium := cloud.BucketFinding{Severity: cloud.SeverityMedium, Type: cloud.BucketNoVersioning, Provider: "aws", Bucket: "noversion-bucket"}
	low := cloud.BucketFinding{Severity: cloud.SeverityLow, Type: cloud.BucketNoLogging, Provider: "aws", Bucket: "nolog-bucket"}

	tests := []struct {
		name        string
		providers   []cloud.StorageProvider
		opts        ScanOptions
		wantBuckets []string
		wantErr     bool
	}{
		{
			name: "single provider returns all findings",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{high, critical}},
			},
			opts:        ScanOptions{},
			wantBuckets: []string{"public-bucket", "unenc-bucket"},
		},
		{
			name: "findings sorted by severity descending",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{low, medium, critical, high}},
			},
			opts:        ScanOptions{},
			wantBuckets: []string{"public-bucket", "unenc-bucket", "noversion-bucket", "nolog-bucket"},
		},
		{
			name: "severity filter excludes low findings",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{critical, high, medium, low}},
			},
			opts:        ScanOptions{MinSeverity: cloud.SeverityHigh},
			wantBuckets: []string{"public-bucket", "unenc-bucket"},
		},
		{
			name: "severity filter keeps only critical",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{critical, high, medium, low}},
			},
			opts:        ScanOptions{MinSeverity: cloud.SeverityCritical},
			wantBuckets: []string{"public-bucket"},
		},
		{
			name: "severity filter at medium includes medium and above",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{critical, high, medium, low}},
			},
			opts:        ScanOptions{MinSeverity: cloud.SeverityMedium},
			wantBuckets: []string{"public-bucket", "unenc-bucket", "noversion-bucket"},
		},
		{
			name: "multiple providers merged and sorted",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{medium}},
				&mockStorageProvider{name: "gcp", findings: []cloud.BucketFinding{critical, high}},
			},
			opts:        ScanOptions{},
			wantBuckets: []string{"public-bucket", "unenc-bucket", "noversion-bucket"},
		},
		{
			name: "same severity sorted by bucket name",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{
					{Severity: cloud.SeverityHigh, Bucket: "z-bucket"},
					{Severity: cloud.SeverityHigh, Bucket: "a-bucket"},
				}},
			},
			opts:        ScanOptions{},
			wantBuckets: []string{"a-bucket", "z-bucket"},
		},
		{
			name: "empty provider returns empty result",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: nil},
			},
			opts:        ScanOptions{},
			wantBuckets: []string{},
		},
		{
			name:        "no providers returns empty result",
			providers:   []cloud.StorageProvider{},
			opts:        ScanOptions{},
			wantBuckets: []string{},
		},
		{
			name: "provider error is returned",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", err: errors.New("credentials expired")},
			},
			opts:    ScanOptions{},
			wantErr: true,
		},
		{
			name: "error from second provider is returned",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{critical}},
				&mockStorageProvider{name: "gcp", err: errors.New("quota exceeded")},
			},
			opts:    ScanOptions{},
			wantErr: true,
		},
		{
			name: "all findings filtered out by severity",
			providers: []cloud.StorageProvider{
				&mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{low, medium}},
			},
			opts:        ScanOptions{MinSeverity: cloud.SeverityCritical},
			wantBuckets: []string{},
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

			if len(got) != len(tt.wantBuckets) {
				t.Fatalf("got %d findings, want %d", len(got), len(tt.wantBuckets))
			}
			for i, bucket := range tt.wantBuckets {
				if got[i].Bucket != bucket {
					t.Errorf("finding[%d]: got Bucket %q, want %q", i, got[i].Bucket, bucket)
				}
			}

			for i := 1; i < len(got); i++ {
				ri := cloud.SeverityRank(got[i].Severity)
				rj := cloud.SeverityRank(got[i-1].Severity)
				if ri > rj {
					t.Errorf("findings not sorted by severity: [%d].Severity=%s > [%d].Severity=%s",
						i, got[i].Severity, i-1, got[i-1].Severity)
				}
			}
		})
	}
}

func TestScanErrorWrapsProviderName(t *testing.T) {
	provider := &mockStorageProvider{name: "mycloud", err: errors.New("auth failed")}
	_, err := Scan(context.Background(), []cloud.StorageProvider{provider}, ScanOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	want := "mycloud: auth failed"
	if err.Error() != want {
		t.Errorf("error message: got %q, want %q", err.Error(), want)
	}
}

func TestScanSeverityFilterBoundary(t *testing.T) {
	finding := cloud.BucketFinding{Severity: cloud.SeverityHigh, Bucket: "test-bucket"}
	provider := &mockStorageProvider{name: "aws", findings: []cloud.BucketFinding{finding}}

	got, err := Scan(context.Background(), []cloud.StorageProvider{provider}, ScanOptions{MinSeverity: cloud.SeverityHigh})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Bucket != "test-bucket" {
		t.Errorf("got Bucket %q, want %q", got[0].Bucket, "test-bucket")
	}
}
