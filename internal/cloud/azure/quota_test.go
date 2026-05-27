package azure

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

type mockComputeUsage struct {
	usages []*armcompute.Usage
	err    error
}

func (m *mockComputeUsage) List(_ context.Context, _ string) ([]*armcompute.Usage, error) {
	return m.usages, m.err
}

type mockNetworkUsage struct {
	usages []*armnetwork.Usage
	err    error
}

func (m *mockNetworkUsage) List(_ context.Context, _ string) ([]*armnetwork.Usage, error) {
	return m.usages, m.err
}

func TestListQuotas(t *testing.T) {
	p := &Provider{
		computeUsage: &mockComputeUsage{usages: []*armcompute.Usage{
			{
				Name:         &armcompute.UsageName{LocalizedValue: to.Ptr("Virtual Machines")},
				CurrentValue: to.Ptr(int32(5)),
				Limit:        to.Ptr(int64(20)),
			},
			{
				CurrentValue: to.Ptr(int32(0)),
				Limit:        to.Ptr(int64(0)), // skipped (Limit 0)
			},
		}},
		networkUsage: &mockNetworkUsage{usages: []*armnetwork.Usage{
			{
				Name:         &armnetwork.UsageName{LocalizedValue: to.Ptr("Public IPs")},
				CurrentValue: to.Ptr(int64(10)),
				Limit:        to.Ptr(int64(100)),
			},
		}},
		storageAccounts: &mockStorageAccounts{accounts: []*armstorage.Account{
			{Name: to.Ptr("sa1")}, {Name: to.Ptr("sa2")},
		}},
	}
	got, err := p.ListQuotas(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1 compute + 1 network + 1 storage = 3
	if len(got) != 3 {
		t.Errorf("expected 3 quotas, got %d: %v", len(got), got)
	}
	byName := map[string]float64{}
	for _, q := range got {
		byName[q.QuotaName] = q.Used
	}
	if byName["Storage Accounts"] != 2 {
		t.Errorf("storage accounts: got %v, want 2", byName["Storage Accounts"])
	}
}

func TestPctAzure(t *testing.T) {
	if pctAzure(0, 0) != 0 {
		t.Error("div by 0 should be 0")
	}
	if pctAzure(50, 100) != 50 {
		t.Error("50/100 should be 50%")
	}
}

func TestInt32PtrVal(t *testing.T) {
	v := int32(42)
	if int32PtrVal(&v) != 42 || int32PtrVal(nil) != 0 {
		t.Error("int32PtrVal broken")
	}
}

func TestInt64PtrVal(t *testing.T) {
	v := int64(42)
	if int64PtrVal(&v) != 42 || int64PtrVal(nil) != 0 {
		t.Error("int64PtrVal broken")
	}
}
