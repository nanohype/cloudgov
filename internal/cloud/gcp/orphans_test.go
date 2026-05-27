package gcp

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockCompute struct {
	disks      []*compute.Disk
	addresses  []*compute.Address
	instances  map[string][]*compute.Instance
	firewalls  []*compute.Firewall
	project    *compute.Project
	disksErr   error
	addrsErr   error
	instErr    error
	fwErr      error
	projectErr error
}

func (m *mockCompute) AggregatedDisks(_ context.Context, _, _ string) ([]*compute.Disk, error) {
	return m.disks, m.disksErr
}
func (m *mockCompute) AggregatedAddresses(_ context.Context, _, _ string) ([]*compute.Address, error) {
	return m.addresses, m.addrsErr
}
func (m *mockCompute) AggregatedInstances(_ context.Context, _ string) (map[string][]*compute.Instance, error) {
	return m.instances, m.instErr
}
func (m *mockCompute) ListFirewalls(_ context.Context, _ string) ([]*compute.Firewall, error) {
	return m.firewalls, m.fwErr
}
func (m *mockCompute) GetProject(_ context.Context, _ string) (*compute.Project, error) {
	if m.project == nil {
		return &compute.Project{}, m.projectErr
	}
	return m.project, m.projectErr
}
func (m *mockCompute) GetFirewall(_ context.Context, _, _ string) (*compute.Firewall, error) {
	return nil, errors.New("not implemented")
}
func (m *mockCompute) GetInstance(_ context.Context, _, _, _ string) (*compute.Instance, error) {
	return nil, errors.New("not implemented")
}

func TestOrphanDisks(t *testing.T) {
	tests := []struct {
		name    string
		disks   []*compute.Disk
		wantIDs []string
	}{
		{
			name: "unattached disk is orphan",
			disks: []*compute.Disk{
				{Id: 1, Name: "disk-1", SizeGb: 100, Type: "pd-standard"}, // no Users
			},
			wantIDs: []string{"1"},
		},
		{
			name: "attached disk is not orphan",
			disks: []*compute.Disk{
				{Id: 1, Name: "in-use", SizeGb: 50, Users: []string{"vm-1"}},
			},
			wantIDs: []string{},
		},
		{
			name:    "no disks returns empty",
			disks:   nil,
			wantIDs: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{projectID: "p", compute: &mockCompute{disks: tt.disks}}
			got, err := p.orphanDisks(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotIDs := make([]string, 0, len(got))
			for _, o := range got {
				gotIDs = append(gotIDs, o.ID)
				if o.Kind != cloud.OrphanDisk || o.Provider != "gcp" {
					t.Errorf("kind/provider: %+v", o)
				}
			}
			if !sameStrings(gotIDs, tt.wantIDs) {
				t.Errorf("ids: got %v, want %v", gotIDs, tt.wantIDs)
			}
		})
	}
}

func TestOrphanDisks_CostEstimation(t *testing.T) {
	// 100 GB * $0.04/GB = $4
	p := &Provider{projectID: "p", compute: &mockCompute{
		disks: []*compute.Disk{{Id: 1, Name: "d", SizeGb: 100}},
	}}
	got, _ := p.orphanDisks(context.Background())
	if got[0].MonthlyCost != 4.0 {
		t.Errorf("cost: got %v, want 4", got[0].MonthlyCost)
	}
}

func TestOrphanDisks_Error(t *testing.T) {
	p := &Provider{projectID: "p", compute: &mockCompute{disksErr: errors.New("api")}}
	_, err := p.orphanDisks(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestOrphanIPs(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []*compute.Address
		wantIDs []string
	}{
		{
			name: "unused reserved IP is orphan",
			addrs: []*compute.Address{
				{Id: 100, Address: "1.2.3.4", Region: "us-central1"},
			},
			wantIDs: []string{"100"},
		},
		{
			name: "IP with users is not orphan",
			addrs: []*compute.Address{
				{Id: 100, Address: "1.2.3.4", Users: []string{"vm"}},
			},
			wantIDs: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{projectID: "p", compute: &mockCompute{addresses: tt.addrs}}
			got, _ := p.orphanIPs(context.Background())
			gotIDs := make([]string, 0, len(got))
			for _, o := range got {
				gotIDs = append(gotIDs, o.ID)
			}
			if !sameStrings(gotIDs, tt.wantIDs) {
				t.Errorf("ids: got %v, want %v", gotIDs, tt.wantIDs)
			}
		})
	}
}

func TestListOrphans_AggregatesBoth(t *testing.T) {
	p := &Provider{projectID: "p", compute: &mockCompute{
		disks:     []*compute.Disk{{Id: 1, Name: "d", SizeGb: 50}},
		addresses: []*compute.Address{{Id: 2, Address: "1.2.3.4"}},
	}}
	got, err := p.ListOrphans(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 (1 disk + 1 ip), got %d", len(got))
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
