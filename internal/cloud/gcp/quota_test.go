package gcp

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/api/compute/v1"
	googleiam "google.golang.org/api/iam/v1"
)

type mockIAMServiceAccounts struct {
	accounts []*googleiam.ServiceAccount
	err      error
}

func (m *mockIAMServiceAccounts) ListServiceAccounts(_ context.Context, _ string) ([]*googleiam.ServiceAccount, error) {
	return m.accounts, m.err
}

func TestListQuotas(t *testing.T) {
	p := &Provider{
		projectID: "my-project",
		compute: &mockCompute{
			project: &compute.Project{Quotas: []*compute.Quota{
				{Metric: "CPUS", Usage: 5, Limit: 24},
				{Metric: "DISKS_TOTAL_GB", Usage: 100, Limit: 2048},
				{Metric: "ZERO", Usage: 0, Limit: 0}, // skipped (Limit <= 0)
			}},
		},
		iamServiceAccounts: &mockIAMServiceAccounts{accounts: []*googleiam.ServiceAccount{
			{Name: "sa-1"}, {Name: "sa-2"},
		}},
	}
	got, err := p.ListQuotas(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 compute quotas (CPUS + DISKS_TOTAL_GB) + 1 IAM quota
	if len(got) != 3 {
		t.Errorf("expected 3 quotas, got %d: %v", len(got), got)
	}
	byName := map[string]float64{}
	for _, q := range got {
		byName[q.QuotaName] = q.Used
	}
	if byName["Service Accounts"] != 2 {
		t.Errorf("Service Accounts used: got %v, want 2", byName["Service Accounts"])
	}
	if byName["CPUS"] != 5 {
		t.Errorf("CPUS used: got %v, want 5", byName["CPUS"])
	}
}

func TestListQuotas_NoProject(t *testing.T) {
	p := &Provider{compute: &mockCompute{}, iamServiceAccounts: &mockIAMServiceAccounts{}}
	_, err := p.ListQuotas(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListQuotas_ComputeError(t *testing.T) {
	p := &Provider{
		projectID: "p",
		compute:   &mockCompute{projectErr: errors.New("api")},
	}
	_, err := p.ListQuotas(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPctGCP(t *testing.T) {
	if pctGCP(50, 100) != 50 {
		t.Error("50/100 should be 50%")
	}
	if pctGCP(0, 0) != 0 {
		t.Error("0/0 should be 0")
	}
}
