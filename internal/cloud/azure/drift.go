package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/drift"
)

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
	client, err := armnetwork.NewSecurityGroupsClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create NSG client: %w", err)
	}

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

	resp, err := client.Get(ctx, rg, name, nil)
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "azurerm_network_security_group",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "NSG not found in Azure",
		}, nil
	}

	actual := map[string]interface{}{
		"name": derefString(resp.Name),
	}
	if resp.Location != nil {
		actual["location"] = *resp.Location
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
	client, err := armstorage.NewAccountsClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create storage accounts client: %w", err)
	}

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

	resp, err := client.GetProperties(ctx, rg, name, nil)
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "azurerm_storage_account",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "storage account not found in Azure",
		}, nil
	}

	actual := map[string]interface{}{
		"name": derefString(resp.Name),
	}
	if resp.Location != nil {
		actual["location"] = *resp.Location
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
	client, err := armcompute.NewVirtualMachinesClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create VM client: %w", err)
	}

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

	resp, err := client.Get(ctx, rg, name, nil)
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "azurerm_virtual_machine",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "virtual machine not found in Azure",
		}, nil
	}

	actual := map[string]interface{}{
		"name": derefString(resp.Name),
	}
	if resp.Location != nil {
		actual["location"] = strings.ToLower(*resp.Location)
	}
	if resp.Properties != nil && resp.Properties.HardwareProfile != nil {
		actual["vm_size"] = string(*resp.Properties.HardwareProfile.VMSize)
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
	client, err := armkeyvault.NewVaultsClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create key vault client: %w", err)
	}

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

	resp, err := client.Get(ctx, rg, name, nil)
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "azurerm_key_vault",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "key vault not found in Azure",
		}, nil
	}

	actual := map[string]interface{}{
		"name": derefString(resp.Name),
	}
	if resp.Location != nil {
		actual["location"] = strings.ToLower(*resp.Location)
	}
	if resp.Properties != nil && resp.Properties.SKU != nil {
		actual["sku_name"] = string(*resp.Properties.SKU.Name)
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
