package gcp

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/run/v2"
	"google.golang.org/api/sqladmin/v1beta4"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockSQLAdmin struct {
	instances []*sqladmin.DatabaseInstance
	instance  *sqladmin.DatabaseInstance
	err       error
}

func (m *mockSQLAdmin) ListInstances(_ context.Context, _ string) ([]*sqladmin.DatabaseInstance, error) {
	return m.instances, m.err
}
func (m *mockSQLAdmin) GetInstance(_ context.Context, _, _ string) (*sqladmin.DatabaseInstance, error) {
	if m.instance == nil {
		return nil, errors.New("not found")
	}
	return m.instance, m.err
}

type mockContainer struct {
	clusters []*container.Cluster
	cluster  *container.Cluster
	err      error
}

func (m *mockContainer) ListClusters(_ context.Context, _ string) ([]*container.Cluster, error) {
	return m.clusters, m.err
}
func (m *mockContainer) GetCluster(_ context.Context, _ string) (*container.Cluster, error) {
	if m.cluster == nil {
		return nil, errors.New("not found")
	}
	return m.cluster, m.err
}

type mockCloudRunV2 struct {
	services []*run.GoogleCloudRunV2Service
	err      error
}

func (m *mockCloudRunV2) ListServices(_ context.Context, _ string) ([]*run.GoogleCloudRunV2Service, error) {
	return m.services, m.err
}

func fullInventoryProvider() *Provider {
	return &Provider{
		projectID: "p",
		compute: &mockCompute{
			instances: map[string][]*compute.Instance{
				"zones/us-central1-a": {{Id: 1, Name: "vm", Zone: "zones/us-central1-a", Status: "RUNNING"}},
			},
		},
		newGCS: func(_ context.Context) (gcsAPI, error) {
			return &mockGCS{buckets: []*storage.BucketAttrs{{Name: "b1", Location: "US"}}}, nil
		},
		sqladmin: &mockSQLAdmin{instances: []*sqladmin.DatabaseInstance{
			{Name: "db1", SelfLink: "link/db1", Region: "us", State: "RUNNABLE"},
		}},
		container: &mockContainer{clusters: []*container.Cluster{
			{Name: "c1", SelfLink: "link/c1", Location: "us-central1", Status: "RUNNING"},
		}},
		cloudRunV2: &mockCloudRunV2{services: []*run.GoogleCloudRunV2Service{
			{Name: "projects/p/locations/us/services/svc1", Uri: "https://svc1.run.app"},
		}},
	}
}

func TestListResources_All(t *testing.T) {
	p := fullInventoryProvider()
	got, err := p.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1 compute + 1 gcs + 1 sql + 1 gke + 1 cloud run = 5
	if len(got) != 5 {
		t.Errorf("expected 5 resources, got %d: %v", len(got), got)
	}
}

func TestListResources_Filter(t *testing.T) {
	p := fullInventoryProvider()
	got, _ := p.ListResources(context.Background(), []string{"compute"})
	if len(got) != 1 || got[0].Type != "compute:instance" {
		t.Errorf("expected only compute:instance, got %v", got)
	}
}

func TestListResources_NoProject(t *testing.T) {
	p := &Provider{}
	_, err := p.ListResources(context.Background(), []string{"compute"})
	if err == nil {
		t.Fatal("expected error for missing project")
	}
}

func TestListResources_KindAssignment(t *testing.T) {
	p := fullInventoryProvider()
	got, _ := p.ListResources(context.Background(), nil)
	wantKinds := map[string]cloud.ResourceKind{
		"compute:instance":  cloud.ResourceCompute,
		"gcs:bucket":        cloud.ResourceStorage,
		"cloudsql:instance": cloud.ResourceDatabase,
		"gke:cluster":       cloud.ResourceContainer,
		"cloudrun:service":  cloud.ResourceServerless,
	}
	for _, r := range got {
		if want, ok := wantKinds[r.Type]; ok && r.Kind != want {
			t.Errorf("type %q kind: got %v, want %v", r.Type, r.Kind, want)
		}
	}
}

func TestZoneToRegion(t *testing.T) {
	tests := []struct{ in, want string }{
		{"zones/us-central1-a", "us-central1"},
		{"us-east1-b", "us-east1"},
		{"global", "global"},
	}
	for _, tt := range tests {
		got := zoneToRegion(tt.in)
		if got != tt.want {
			t.Errorf("zoneToRegion(%q): got %q, want %q", tt.in, got, tt.want)
		}
	}
}
