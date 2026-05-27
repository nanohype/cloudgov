package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockDisks struct {
	disks []*armcompute.Disk
	err   error
}

func (m *mockDisks) List(_ context.Context) ([]*armcompute.Disk, error) {
	return m.disks, m.err
}

type mockPublicIPs struct {
	ips []*armnetwork.PublicIPAddress
	err error
}

func (m *mockPublicIPs) ListAll(_ context.Context) ([]*armnetwork.PublicIPAddress, error) {
	return m.ips, m.err
}

func TestOrphanDisks(t *testing.T) {
	unattached := armcompute.DiskStateUnattached
	attached := armcompute.DiskStateAttached
	p := &Provider{disks: &mockDisks{disks: []*armcompute.Disk{
		{ID: to.Ptr("/disk/1"), Name: to.Ptr("d1"), Location: to.Ptr("eastus"),
			Properties: &armcompute.DiskProperties{DiskState: &unattached, DiskSizeGB: to.Ptr(int32(100))}},
		{ID: to.Ptr("/disk/2"), Name: to.Ptr("d2"),
			Properties: &armcompute.DiskProperties{DiskState: &attached, DiskSizeGB: to.Ptr(int32(50))}},
	}}}
	got, err := p.orphanDisks(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].MonthlyCost != 5.0 {
		t.Errorf("expected 1 orphan disk with cost 5, got %v", got)
	}
}

func TestOrphanIPs(t *testing.T) {
	p := &Provider{publicIPs: &mockPublicIPs{ips: []*armnetwork.PublicIPAddress{
		{ID: to.Ptr("/ip/1"), Name: to.Ptr("ip1"), Location: to.Ptr("eastus"),
			Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: to.Ptr("1.2.3.4")}},
		{ID: to.Ptr("/ip/2"), Name: to.Ptr("ip2"),
			Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPConfiguration: &armnetwork.IPConfiguration{}}},
	}}}
	got, err := p.orphanIPs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Kind != cloud.OrphanIP {
		t.Errorf("expected 1 orphan ip, got %v", got)
	}
}

func TestListOrphans(t *testing.T) {
	unattached := armcompute.DiskStateUnattached
	p := &Provider{
		disks: &mockDisks{disks: []*armcompute.Disk{
			{ID: to.Ptr("/disk/1"), Name: to.Ptr("d"),
				Properties: &armcompute.DiskProperties{DiskState: &unattached, DiskSizeGB: to.Ptr(int32(10))}},
		}},
		publicIPs: &mockPublicIPs{ips: []*armnetwork.PublicIPAddress{
			{ID: to.Ptr("/ip/1"), Name: to.Ptr("ip"),
				Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: to.Ptr("1.2.3.4")}},
		}},
	}
	got, err := p.ListOrphans(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 (1 disk + 1 ip), got %d", len(got))
	}
}

func TestListOrphans_DiskError(t *testing.T) {
	p := &Provider{
		disks:     &mockDisks{err: errors.New("api")},
		publicIPs: &mockPublicIPs{},
	}
	_, err := p.ListOrphans(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPtrStr(t *testing.T) {
	s := "hello"
	if ptrStr(&s) != "hello" || ptrStr(nil) != "" {
		t.Error("ptrStr broken")
	}
}
