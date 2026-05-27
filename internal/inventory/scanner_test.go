package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockInventoryProvider struct {
	name      string
	resources []cloud.InventoryResource
	err       error
}

func (m *mockInventoryProvider) Name() string                 { return m.name }
func (m *mockInventoryProvider) Detect(_ context.Context) bool { return true }
func (m *mockInventoryProvider) ListResources(_ context.Context, _ []string) ([]cloud.InventoryResource, error) {
	return m.resources, m.err
}

func TestScan(t *testing.T) {
	now := time.Now()
	provider := &mockInventoryProvider{
		name: "mock",
		resources: []cloud.InventoryResource{
			{Kind: cloud.ResourceCompute, Type: "ec2:instance", ID: "i-123", Name: "web-1", Provider: "mock", Region: "us-east-1", CreatedAt: &now},
			{Kind: cloud.ResourceStorage, Type: "s3:bucket", ID: "my-bucket", Name: "my-bucket", Provider: "mock", Region: "us-east-1"},
			{Kind: cloud.ResourceDatabase, Type: "rds:instance", ID: "db-1", Name: "prod-db", Provider: "mock", Region: "us-west-2"},
		},
	}

	resources, err := Scan(context.Background(), []cloud.InventoryProvider{provider}, ScanOptions{})
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(resources))
	}

	// Check sorting: compute < database < storage by kind
	if resources[0].Kind != cloud.ResourceCompute {
		t.Errorf("expected first resource to be compute, got %s", resources[0].Kind)
	}
	if resources[1].Kind != cloud.ResourceDatabase {
		t.Errorf("expected second resource to be database, got %s", resources[1].Kind)
	}
	if resources[2].Kind != cloud.ResourceStorage {
		t.Errorf("expected third resource to be storage, got %s", resources[2].Kind)
	}
}

func TestScan_MultipleProviders(t *testing.T) {
	p1 := &mockInventoryProvider{
		name: "aws",
		resources: []cloud.InventoryResource{
			{Kind: cloud.ResourceCompute, Type: "ec2:instance", ID: "i-1", Provider: "aws", Region: "us-east-1"},
		},
	}
	p2 := &mockInventoryProvider{
		name: "gcp",
		resources: []cloud.InventoryResource{
			{Kind: cloud.ResourceCompute, Type: "compute:instance", ID: "vm-1", Provider: "gcp", Region: "us-central1"},
		},
	}

	resources, err := Scan(context.Background(), []cloud.InventoryProvider{p1, p2}, ScanOptions{})
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}

	// Should be sorted by provider: aws < gcp
	if resources[0].Provider != "aws" {
		t.Errorf("expected first resource from aws, got %s", resources[0].Provider)
	}
	if resources[1].Provider != "gcp" {
		t.Errorf("expected second resource from gcp, got %s", resources[1].Provider)
	}
}

func TestScan_Empty(t *testing.T) {
	provider := &mockInventoryProvider{name: "mock"}
	resources, err := Scan(context.Background(), []cloud.InventoryProvider{provider}, ScanOptions{})
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources, got %d", len(resources))
	}
}

func TestSummarize(t *testing.T) {
	resources := []cloud.InventoryResource{
		{Kind: cloud.ResourceCompute, Type: "ec2:instance", Region: "us-east-1"},
		{Kind: cloud.ResourceCompute, Type: "ec2:instance", Region: "us-east-1"},
		{Kind: cloud.ResourceStorage, Type: "s3:bucket", Region: "us-west-2"},
		{Kind: cloud.ResourceDatabase, Type: "rds:instance", Region: "us-west-2"},
	}

	s := Summarize(resources)

	if s.Total != 4 {
		t.Errorf("expected total 4, got %d", s.Total)
	}
	if s.ByKind[cloud.ResourceCompute] != 2 {
		t.Errorf("expected 2 compute, got %d", s.ByKind[cloud.ResourceCompute])
	}
	if s.ByKind[cloud.ResourceStorage] != 1 {
		t.Errorf("expected 1 storage, got %d", s.ByKind[cloud.ResourceStorage])
	}
	if s.ByType["ec2:instance"] != 2 {
		t.Errorf("expected 2 ec2:instance, got %d", s.ByType["ec2:instance"])
	}
	if s.ByRegion["us-east-1"] != 2 {
		t.Errorf("expected 2 in us-east-1, got %d", s.ByRegion["us-east-1"])
	}
	if s.ByRegion["us-west-2"] != 2 {
		t.Errorf("expected 2 in us-west-2, got %d", s.ByRegion["us-west-2"])
	}
}
