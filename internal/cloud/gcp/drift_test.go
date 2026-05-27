package gcp

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/sqladmin/v1beta4"
	cstorage "google.golang.org/api/storage/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockGCSRest struct {
	bucket *cstorage.Bucket
	err    error
}

func (m *mockGCSRest) GetBucket(_ context.Context, _ string) (*cstorage.Bucket, error) {
	return m.bucket, m.err
}

// driftMockCompute extends mockCompute with Get-by-name implementations.
type driftMockCompute struct {
	mockCompute
	fw         *compute.Firewall
	fwErr2     error
	inst       *compute.Instance
	instGetErr error
}

func (m *driftMockCompute) GetFirewall(_ context.Context, _, _ string) (*compute.Firewall, error) {
	return m.fw, m.fwErr2
}
func (m *driftMockCompute) GetInstance(_ context.Context, _, _, _ string) (*compute.Instance, error) {
	return m.inst, m.instGetErr
}

func google404() error {
	return &googleapi.Error{Code: 404}
}

func TestSupportedResourceTypes(t *testing.T) {
	p := &Provider{}
	got := p.SupportedResourceTypes()
	if len(got) == 0 {
		t.Fatal("expected supported types")
	}
	want := "google_compute_firewall"
	found := false
	for _, g := range got {
		if g == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in supported types", want)
	}
}

func TestCheckDrift_Unsupported(t *testing.T) {
	p := &Provider{}
	got, err := p.CheckDrift(context.Background(), "google_widget", "x", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != cloud.DriftError {
		t.Errorf("status: got %v, want DriftError", got.Status)
	}
}

func TestCheckFirewallDrift_InSync(t *testing.T) {
	p := &Provider{projectID: "p", compute: &driftMockCompute{
		fw: &compute.Firewall{Name: "fw", Description: "web tier", Direction: "INGRESS",
			Disabled: false, Priority: 1000},
	}}
	got, _ := p.CheckDrift(context.Background(), "google_compute_firewall", "fw",
		map[string]interface{}{"name": "fw", "description": "web tier", "direction": "INGRESS",
			"disabled": "false", "priority": "1000"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckFirewallDrift_Deleted(t *testing.T) {
	p := &Provider{projectID: "p", compute: &driftMockCompute{fwErr2: google404()}}
	got, _ := p.CheckDrift(context.Background(), "google_compute_firewall", "fw", nil)
	if got.Status != cloud.DriftDeleted {
		t.Errorf("status: got %v, want DriftDeleted", got.Status)
	}
}

func TestCheckStorageBucketDrift_InSync(t *testing.T) {
	p := &Provider{projectID: "p", gcsREST: &mockGCSRest{
		bucket: &cstorage.Bucket{Name: "b", Location: "us", StorageClass: "STANDARD"},
	}}
	got, _ := p.CheckDrift(context.Background(), "google_storage_bucket", "b",
		map[string]interface{}{"name": "b", "location": "us", "storage_class": "STANDARD"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckStorageBucketDrift_Deleted(t *testing.T) {
	p := &Provider{projectID: "p", gcsREST: &mockGCSRest{err: google404()}}
	got, _ := p.CheckDrift(context.Background(), "google_storage_bucket", "missing", nil)
	if got.Status != cloud.DriftDeleted {
		t.Errorf("status: got %v, want DriftDeleted", got.Status)
	}
}

func TestCheckComputeInstanceDrift_NoZone(t *testing.T) {
	p := &Provider{projectID: "p", compute: &driftMockCompute{}}
	got, _ := p.CheckDrift(context.Background(), "google_compute_instance", "i", nil)
	if got.Status != cloud.DriftError {
		t.Errorf("status: got %v, want DriftError", got.Status)
	}
}

func TestCheckComputeInstanceDrift_Modified(t *testing.T) {
	p := &Provider{projectID: "p", compute: &driftMockCompute{
		inst: &compute.Instance{Name: "i", MachineType: "zones/us-central1-a/machineTypes/n2-standard-4"},
	}}
	got, _ := p.CheckDrift(context.Background(), "google_compute_instance", "i",
		map[string]interface{}{"name": "i", "machine_type": "e2-medium", "zone": "us-central1-a"})
	if got.Status != cloud.DriftModified {
		t.Errorf("status: got %v, want DriftModified", got.Status)
	}
}

func TestCheckSQLInstanceDrift_InSync(t *testing.T) {
	p := &Provider{projectID: "p", sqladmin: &mockSQLAdmin{
		instance: &sqladmin.DatabaseInstance{DatabaseVersion: "MYSQL_8_0",
			Settings: &sqladmin.Settings{Tier: "db-n1-standard-1"}},
	}}
	got, _ := p.CheckDrift(context.Background(), "google_sql_database_instance", "db",
		map[string]interface{}{"database_version": "MYSQL_8_0", "tier": "db-n1-standard-1"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckGKEClusterDrift_NoLocation(t *testing.T) {
	p := &Provider{projectID: "p", container: &mockContainer{}}
	got, _ := p.CheckDrift(context.Background(), "google_container_cluster", "c", nil)
	if got.Status != cloud.DriftError {
		t.Errorf("status: got %v, want DriftError", got.Status)
	}
}

func TestCheckGKEClusterDrift_InSync(t *testing.T) {
	p := &Provider{projectID: "p", container: &mockContainer{
		cluster: &container.Cluster{Name: "c", CurrentMasterVersion: "1.27.5", CurrentNodeVersion: "1.27.5"},
	}}
	got, _ := p.CheckDrift(context.Background(), "google_container_cluster", "c",
		map[string]interface{}{"name": "c", "min_master_version": "1.27.5",
			"node_version": "1.27.5", "location": "us-central1"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestIsGoogleNotFound(t *testing.T) {
	if !isGoogleNotFound(google404()) {
		t.Error("expected 404 to be recognized as not found")
	}
	if isGoogleNotFound(&googleapi.Error{Code: 500}) {
		t.Error("500 should not be not-found")
	}
	if isGoogleNotFound(errors.New("plain")) {
		t.Error("plain error should not be not-found")
	}
}
