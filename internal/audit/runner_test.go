package audit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

var errScanFailed = errors.New("access denied")

type mockStorageProvider struct {
	findings []cloud.BucketFinding
	err      error
}

func (m *mockStorageProvider) Name() string                  { return "mock" }
func (m *mockStorageProvider) Detect(_ context.Context) bool { return true }
func (m *mockStorageProvider) AuditStorage(_ context.Context) ([]cloud.BucketFinding, error) {
	return m.findings, m.err
}

type mockNetworkProvider struct {
	findings []cloud.NetworkFinding
	err      error
}

func (m *mockNetworkProvider) Name() string                  { return "mock" }
func (m *mockNetworkProvider) Detect(_ context.Context) bool { return true }
func (m *mockNetworkProvider) AuditNetwork(_ context.Context) ([]cloud.NetworkFinding, error) {
	return m.findings, m.err
}

type mockOrphansProvider struct {
	orphans []cloud.OrphanResource
	err     error
}

func (m *mockOrphansProvider) Name() string                  { return "mock" }
func (m *mockOrphansProvider) Detect(_ context.Context) bool { return true }
func (m *mockOrphansProvider) ListOrphans(_ context.Context) ([]cloud.OrphanResource, error) {
	return m.orphans, m.err
}

type mockCertProvider struct {
	findings []cloud.CertFinding
	err      error
}

func (m *mockCertProvider) Name() string                  { return "mock" }
func (m *mockCertProvider) Detect(_ context.Context) bool { return true }
func (m *mockCertProvider) ListCertificates(_ context.Context) ([]cloud.CertFinding, error) {
	return m.findings, m.err
}

type mockSecretsProvider struct {
	findings []cloud.SecretFinding
	err      error
}

func (m *mockSecretsProvider) Name() string                  { return "mock" }
func (m *mockSecretsProvider) Detect(_ context.Context) bool { return true }
func (m *mockSecretsProvider) ScanSecrets(_ context.Context) ([]cloud.SecretFinding, error) {
	return m.findings, m.err
}

func TestRun_AllDomains(t *testing.T) {
	providers := Providers{
		Storage: []cloud.StorageProvider{&mockStorageProvider{
			findings: []cloud.BucketFinding{
				{Severity: cloud.SeverityHigh, Type: cloud.BucketPublicAccess, Provider: "mock", Bucket: "test-bucket"},
			},
		}},
		Network: []cloud.NetworkProvider{&mockNetworkProvider{
			findings: []cloud.NetworkFinding{
				{Severity: cloud.SeverityCritical, Type: cloud.NetworkAdminPortOpen, Provider: "mock", Resource: "sg-123"},
			},
		}},
		Orphans: []cloud.OrphansProvider{&mockOrphansProvider{
			orphans: []cloud.OrphanResource{
				{Kind: cloud.OrphanDisk, ID: "vol-1", Provider: "mock", MonthlyCost: 25.0},
			},
		}},
		Certs: []cloud.CertProvider{&mockCertProvider{
			findings: []cloud.CertFinding{
				{Severity: cloud.SeverityHigh, Provider: "mock", Domain: "example.com"},
			},
		}},
		Secrets: []cloud.SecretsProvider{&mockSecretsProvider{
			findings: []cloud.SecretFinding{
				{Severity: cloud.SeverityCritical, Type: cloud.SecretAWSAccessKey, Provider: "mock"},
			},
		}},
	}

	report, err := Run(context.Background(), providers, Options{Quiet: true})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(report.Storage) != 1 {
		t.Errorf("expected 1 storage finding, got %d", len(report.Storage))
	}
	if len(report.Network) != 1 {
		t.Errorf("expected 1 network finding, got %d", len(report.Network))
	}
	if len(report.Orphans) != 1 {
		t.Errorf("expected 1 orphan, got %d", len(report.Orphans))
	}
	if len(report.Certs) != 1 {
		t.Errorf("expected 1 cert finding, got %d", len(report.Certs))
	}
	if len(report.Secrets) != 1 {
		t.Errorf("expected 1 secret finding, got %d", len(report.Secrets))
	}

	if report.Summary.TotalFindings != 5 {
		t.Errorf("expected 5 total findings, got %d", report.Summary.TotalFindings)
	}
	if report.Summary.BySeverity["CRITICAL"] != 2 {
		t.Errorf("expected 2 critical, got %d", report.Summary.BySeverity["CRITICAL"])
	}
	if report.Summary.BySeverity["HIGH"] != 2 {
		t.Errorf("expected 2 high, got %d", report.Summary.BySeverity["HIGH"])
	}
	if report.Summary.OrphanCost != 25.0 {
		t.Errorf("expected orphan cost $25.00, got $%.2f", report.Summary.OrphanCost)
	}
	if report.Duration == "" {
		t.Error("expected non-empty duration")
	}
}

func TestRun_SkipDomains(t *testing.T) {
	providers := Providers{
		Storage: []cloud.StorageProvider{&mockStorageProvider{
			findings: []cloud.BucketFinding{
				{Severity: cloud.SeverityHigh, Provider: "mock", Bucket: "b1"},
			},
		}},
		Network: []cloud.NetworkProvider{&mockNetworkProvider{
			findings: []cloud.NetworkFinding{
				{Severity: cloud.SeverityHigh, Provider: "mock", Resource: "sg-1"},
			},
		}},
	}

	report, err := Run(context.Background(), providers, Options{
		Skip:  map[string]bool{"storage": true},
		Quiet: true,
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(report.Storage) != 0 {
		t.Errorf("expected 0 storage findings (skipped), got %d", len(report.Storage))
	}
	if len(report.Network) != 1 {
		t.Errorf("expected 1 network finding, got %d", len(report.Network))
	}
	if report.Summary.DomainsSkipped != 1 {
		t.Errorf("expected 1 domain skipped, got %d", report.Summary.DomainsSkipped)
	}
}

func TestRun_Empty(t *testing.T) {
	report, err := Run(context.Background(), Providers{}, Options{Quiet: true})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if report.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", report.Summary.TotalFindings)
	}
}

// ── incompleteness ────────────────────────────────────────────────────────────
//
// A domain that could not be fully read contributes zero findings, and zero
// findings is otherwise indistinguishable from a clean domain. The exit code is
// consumed as merge-gate evidence where 0 affirmatively supports approval, so a
// partial view has to surface as one — for the aggregate audit exactly as it
// already does for each per-domain command.

// incompleteStorageProvider reports through the warn channel the way a real
// provider does when a paginator or a per-bucket call fails partway.
type incompleteStorageProvider struct {
	mockStorageProvider
	warnings []string
}

func (p *incompleteStorageProvider) Incomplete() []string { return p.warnings }

func TestRun_SurfacesProviderWarningsAsIncomplete(t *testing.T) {
	p := &incompleteStorageProvider{warnings: []string{"s3: GetBucketVersioning denied for acme-logs"}}
	report, err := Run(context.Background(), Providers{
		Storage: []cloud.StorageProvider{p},
	}, Options{Quiet: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(report.Incomplete) != 1 || report.Incomplete[0] != p.warnings[0] {
		t.Fatalf("expected the provider warning to reach report.Incomplete, got %v", report.Incomplete)
	}
}

func TestRun_SurfacesAFailedDomainAsIncomplete(t *testing.T) {
	// A denied ListBuckets returns an error, the domain yields nothing, and
	// before this the only trace was a stderr line the exit code never saw.
	report, err := Run(context.Background(), Providers{
		Storage: []cloud.StorageProvider{&mockStorageProvider{err: errScanFailed}},
	}, Options{Quiet: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(report.Incomplete) == 0 {
		t.Fatal("a domain whose scan failed must not report as a complete, clean domain")
	}
	if !strings.Contains(report.Incomplete[0], "storage") {
		t.Fatalf("expected the failing domain to be named, got %q", report.Incomplete[0])
	}
}

func TestRun_CleanScanReportsNothingIncomplete(t *testing.T) {
	report, err := Run(context.Background(), Providers{
		Storage: []cloud.StorageProvider{&mockStorageProvider{}},
	}, Options{Quiet: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(report.Incomplete) != 0 {
		t.Fatalf("a fully-observed scan is not incomplete, got %v", report.Incomplete)
	}
}

func TestRun_SkippedDomainIsNotIncomplete(t *testing.T) {
	// `--skip storage` is the operator choosing not to look. The summary
	// already reports it as skipped; counting it as unobserved would make the
	// flag raise the incomplete exit code.
	p := &incompleteStorageProvider{warnings: []string{"s3: denied"}}
	report, err := Run(context.Background(), Providers{
		Storage: []cloud.StorageProvider{p},
	}, Options{Quiet: true, Skip: map[string]bool{"storage": true}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(report.Incomplete) != 0 {
		t.Fatalf("a skipped domain is not an incomplete one, got %v", report.Incomplete)
	}
}

func TestRun_GathersIncompleteAcrossDomains(t *testing.T) {
	storage := &incompleteStorageProvider{warnings: []string{"s3: denied"}}
	report, err := Run(context.Background(), Providers{
		Storage: []cloud.StorageProvider{storage},
		Certs:   []cloud.CertProvider{&mockCertProvider{err: errScanFailed}},
	}, Options{Quiet: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(report.Incomplete) != 2 {
		t.Fatalf("expected both the warning and the failed domain, got %v", report.Incomplete)
	}
}
