package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/drift"
)

// vmsAPI is the narrow Virtual Machines surface used by this package.
type vmsAPI interface {
	Get(ctx context.Context, resourceGroup, name string) (*armcompute.VirtualMachine, error)
}

type vmsAdapter struct {
	client *armcompute.VirtualMachinesClient
}

func (a *vmsAdapter) Get(ctx context.Context, rg, name string) (*armcompute.VirtualMachine, error) {
	resp, err := a.client.Get(ctx, rg, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualMachine, nil
}

// SupportedResourceTypes returns the Terraform resource types this provider can check for drift.
func (p *Provider) SupportedResourceTypes() []string {
	return []string{
		"azurerm_network_security_group",
		"azurerm_storage_account",
		"azurerm_virtual_machine",
		"azurerm_key_vault",
	}
}

// CheckDrift compares live Azure state against the provided Terraform attributes.
func (p *Provider) CheckDrift(ctx context.Context, resourceType, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	switch resourceType {
	case "azurerm_network_security_group":
		return p.checkNSGDrift(ctx, resourceID, attrs)
	case "azurerm_storage_account":
		return p.checkStorageAccountDrift(ctx, resourceID, attrs)
	case "azurerm_virtual_machine":
		return p.checkVirtualMachineDrift(ctx, resourceID, attrs)
	case "azurerm_key_vault":
		return p.checkKeyVaultDrift(ctx, resourceID, attrs)
	default:
		return cloud.DriftResult{
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "unsupported resource type",
		}, nil
	}
}

func (p *Provider) checkNSGDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	rg := resourceGroupFromID(&resourceID)
	name := nameFromAttrs(attrs)
	if rg == "" || name == "" {
		return cloud.DriftResult{
			ResourceType: "azurerm_network_security_group",
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "cannot determine resource group or name from attributes",
		}, nil
	}

	nsg, err := p.nsgs.Get(ctx, rg, name)
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "azurerm_network_security_group",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "NSG not found in Azure",
		}, nil
	}

	actual := map[string]interface{}{
		"name": derefString(nsg.Name),
	}
	if nsg.Location != nil {
		actual["location"] = *nsg.Location
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "location"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "azurerm_network_security_group",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "azurerm_network_security_group",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkStorageAccountDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	rg := resourceGroupFromID(&resourceID)
	name := nameFromAttrs(attrs)
	if rg == "" || name == "" {
		return cloud.DriftResult{
			ResourceType: "azurerm_storage_account",
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "cannot determine resource group or name from attributes",
		}, nil
	}

	acct, err := p.storageAccounts.GetProperties(ctx, rg, name)
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "azurerm_storage_account",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "storage account not found in Azure",
		}, nil
	}

	actual := map[string]interface{}{
		"name": derefString(acct.Name),
	}
	if acct.Location != nil {
		actual["location"] = *acct.Location
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "location"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "azurerm_storage_account",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "azurerm_storage_account",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkVirtualMachineDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	rg := resourceGroupFromID(&resourceID)
	name := nameFromAttrs(attrs)
	if rg == "" || name == "" {
		return cloud.DriftResult{
			ResourceType: "azurerm_virtual_machine",
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "cannot determine resource group or name from attributes",
		}, nil
	}

	vm, err := p.vms.Get(ctx, rg, name)
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "azurerm_virtual_machine",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "virtual machine not found in Azure",
		}, nil
	}

	actual := map[string]interface{}{
		"name": derefString(vm.Name),
	}
	if vm.Location != nil {
		actual["location"] = strings.ToLower(*vm.Location)
	}
	if vm.Properties != nil && vm.Properties.HardwareProfile != nil {
		actual["vm_size"] = string(*vm.Properties.HardwareProfile.VMSize)
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "location", "vm_size"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "azurerm_virtual_machine",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "azurerm_virtual_machine",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkKeyVaultDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	rg := resourceGroupFromID(&resourceID)
	name := nameFromAttrs(attrs)
	if rg == "" || name == "" {
		return cloud.DriftResult{
			ResourceType: "azurerm_key_vault",
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "cannot determine resource group or name from attributes",
		}, nil
	}

	kv, err := p.keyVaults.Get(ctx, rg, name)
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "azurerm_key_vault",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "key vault not found in Azure",
		}, nil
	}

	actual := map[string]interface{}{
		"name": derefString(kv.Name),
	}
	if kv.Location != nil {
		actual["location"] = strings.ToLower(*kv.Location)
	}
	if kv.Properties != nil && kv.Properties.SKU != nil {
		actual["sku_name"] = string(*kv.Properties.SKU.Name)
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "location", "sku_name"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "azurerm_key_vault",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "azurerm_key_vault",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func nameFromAttrs(attrs map[string]interface{}) string {
	if name, ok := attrs["name"]; ok {
		if s, ok := name.(string); ok {
			return s
		}
	}
	return ""
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
