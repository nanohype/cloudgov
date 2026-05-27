package audit

import (
	"context"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockIAMProvider struct {
	name       string
	findings   []cloud.Finding
	principals []cloud.Principal
	err        error
}

func (m *mockIAMProvider) Name() string                 { return m.name }
func (m *mockIAMProvider) Detect(_ context.Context) bool { return true }
func (m *mockIAMProvider) ListPrincipals(_ context.Context) ([]cloud.Principal, error) {
	return m.principals, m.err
}
func (m *mockIAMProvider) GrantedPermissions(_ context.Context, _ cloud.Principal) ([]cloud.Permission, error) {
	return nil, nil
}
func (m *mockIAMProvider) UsedPermissions(_ context.Context, _ cloud.Principal, _ interface{}) ([]cloud.Permission, error) {
	return nil, nil
}
func (m *mockIAMProvider) MinimalPolicy(_ context.Context, _ cloud.Principal, _ []cloud.Permission) (cloud.Policy, error) {
	return cloud.Policy{}, nil
}

type mockStorageProvider struct {
	findings []cloud.BucketFinding
	err      error
}

func (m *mockStorageProvider) Name() string                 { return "mock" }
func (m *mockStorageProvider) Detect(_ context.Context) bool { return true }
func (m *mockStorageProvider) AuditStorage(_ context.Context) ([]cloud.BucketFinding, error) {
	return m.findings, m.err
}

type mockNetworkProvider struct {
	findings []cloud.NetworkFinding
	err      error
}

func (m *mockNetworkProvider) Name() string                 { return "mock" }
func (m *mockNetworkProvider) Detect(_ context.Context) bool { return true }
func (m *mockNetworkProvider) AuditNetwork(_ context.Context) ([]cloud.NetworkFinding, error) {
	return m.findings, m.err
}

type mockOrphansProvider struct {
	orphans []cloud.OrphanResource
	err     error
}

func (m *mockOrphansProvider) Name() string                 { return "mock" }
func (m *mockOrphansProvider) Detect(_ context.Context) bool { return true }
func (m *mockOrphansProvider) ListOrphans(_ context.Context) ([]cloud.OrphanResource, error) {
	return m.orphans, m.err
}

type mockCertProvider struct {
	findings []cloud.CertFinding
	err      error
}

func (m *mockCertProvider) Name() string                 { return "mock" }
func (m *mockCertProvider) Detect(_ context.Context) bool { return true }
func (m *mockCertProvider) ListCertificates(_ context.Context) ([]cloud.CertFinding, error) {
	return m.findings, m.err
}

type mockSecretsProvider struct {
	findings []cloud.SecretFinding
	err      error
}

func (m *mockSecretsProvider) Name() string                 { return "mock" }
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
