package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockVMs struct {
	vm  *armcompute.VirtualMachine
	err error
}

func (m *mockVMs) Get(_ context.Context, _, _ string) (*armcompute.VirtualMachine, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.vm, nil
}

func TestSupportedResourceTypes(t *testing.T) {
	p := &Provider{}
	got := p.SupportedResourceTypes()
	if len(got) == 0 {
		t.Fatal("expected supported types")
	}
}

func TestCheckDrift_Unsupported(t *testing.T) {
	p := &Provider{}
	got, _ := p.CheckDrift(context.Background(), "azurerm_widget", "x", nil)
	if got.Status != cloud.DriftError {
		t.Errorf("status: got %v, want DriftError", got.Status)
	}
}

func TestCheckNSGDrift_NoResourceGroup(t *testing.T) {
	p := &Provider{nsgs: &mockNSG{}}
	got, _ := p.CheckDrift(context.Background(), "x", "nsg-x", nil)
	if got.Status != cloud.DriftError {
		t.Errorf("status: got %v, want DriftError", got.Status)
	}
}

func TestCheckNSGDrift_InSync(t *testing.T) {
	p := &Provider{nsgs: &mockNSG{nsg: &armnetwork.SecurityGroup{
		Name:     to.Ptr("nsg-1"),
		Location: to.Ptr("eastus"),
	}}}
	resID := "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1"
	got, _ := p.CheckDrift(context.Background(), "azurerm_network_security_group", resID,
		map[string]interface{}{"name": "nsg-1", "location": "eastus"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckNSGDrift_Deleted(t *testing.T) {
	p := &Provider{nsgs: &mockNSG{}}
	resID := "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1"
	got, _ := p.CheckDrift(context.Background(), "azurerm_network_security_group", resID,
		map[string]interface{}{"name": "nsg-1"})
	if got.Status != cloud.DriftDeleted {
		t.Errorf("status: got %v, want DriftDeleted", got.Status)
	}
}

func TestCheckStorageAccountDrift_InSync(t *testing.T) {
	p := &Provider{storageAccounts: &mockStorageAccounts{props: &armstorage.Account{
		Name:     to.Ptr("sa-1"),
		Location: to.Ptr("eastus"),
	}}}
	resID := "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa-1"
	got, _ := p.CheckDrift(context.Background(), "azurerm_storage_account", resID,
		map[string]interface{}{"name": "sa-1", "location": "eastus"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckVirtualMachineDrift_Modified(t *testing.T) {
	vmsize := armcompute.VirtualMachineSizeTypesStandardD2SV3
	p := &Provider{vms: &mockVMs{vm: &armcompute.VirtualMachine{
		Name:     to.Ptr("vm-1"),
		Location: to.Ptr("eastus"),
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{VMSize: &vmsize},
		},
	}}}
	resID := "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
	got, _ := p.CheckDrift(context.Background(), "azurerm_virtual_machine", resID,
		map[string]interface{}{"name": "vm-1", "location": "eastus", "vm_size": "Standard_DS3_v2"})
	if got.Status != cloud.DriftModified {
		t.Errorf("status: got %v, want DriftModified", got.Status)
	}
}

func TestCheckVirtualMachineDrift_Deleted(t *testing.T) {
	p := &Provider{vms: &mockVMs{err: errors.New("not found")}}
	resID := "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
	got, _ := p.CheckDrift(context.Background(), "azurerm_virtual_machine", resID,
		map[string]interface{}{"name": "vm-1"})
	if got.Status != cloud.DriftDeleted {
		t.Errorf("status: got %v, want DriftDeleted", got.Status)
	}
}

func TestCheckKeyVaultDrift_InSync(t *testing.T) {
	sku := armkeyvault.SKUNameStandard
	p := &Provider{keyVaults: &mockKeyVaults{vault: &armkeyvault.Vault{
		Name:     to.Ptr("kv-1"),
		Location: to.Ptr("eastus"),
		Properties: &armkeyvault.VaultProperties{
			SKU: &armkeyvault.SKU{Name: &sku},
		},
	}}}
	resID := "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1"
	got, _ := p.CheckDrift(context.Background(), "azurerm_key_vault", resID,
		map[string]interface{}{"name": "kv-1", "location": "eastus", "sku_name": "standard"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestNameFromAttrs(t *testing.T) {
	if got := nameFromAttrs(map[string]interface{}{"name": "x"}); got != "x" {
		t.Errorf("got %q, want x", got)
	}
	if got := nameFromAttrs(nil); got != "" {
		t.Errorf("nil attrs should return empty, got %q", got)
	}
	if got := nameFromAttrs(map[string]interface{}{"name": 42}); got != "" {
		t.Errorf("non-string name should return empty, got %q", got)
	}
}

func TestDerefString(t *testing.T) {
	s := "hello"
	if derefString(&s) != "hello" || derefString(nil) != "" {
		t.Error("derefString broken")
	}
}
