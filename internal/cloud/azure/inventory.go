package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/stxkxs/matlock/internal/cloud"
)

// ListResources lists Azure resources for inventory.
func (p *Provider) ListResources(ctx context.Context, typeFilter []string) ([]cloud.InventoryResource, error) {
	if p.subscriptionID == "" {
		return nil, fmt.Errorf("AZURE_SUBSCRIPTION_ID not set")
	}

	all := len(typeFilter) == 0
	filter := make(map[string]bool)
	for _, t := range typeFilter {
		filter[strings.ToLower(t)] = true
	}

	resourcesList, err := p.resources.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}

	var resources []cloud.InventoryResource
	for _, r := range resourcesList {
		resType := derefStr(r.Type)
		normalType := normalizeAzureType(resType)
		if !all && !filter[strings.ToLower(normalType)] && !filter[strings.ToLower(resType)] {
			continue
		}
		tags := azureTagsToMap(r.Tags)
		id := derefStr(r.ID)
		name := derefStr(r.Name)
		location := derefStr(r.Location)
		resources = append(resources, cloud.InventoryResource{
			Kind:     azureResourceKind(resType),
			Type:     normalType,
			ID:       id,
			Name:     name,
			Provider: "azure",
			Region:   location,
			Tags:     tags,
		})
	}
	return resources, nil
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func azureTagsToMap(tags map[string]*string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for k, v := range tags {
		if v != nil {
			m[k] = *v
		}
	}
	return m
}

func normalizeAzureType(t string) string {
	// "Microsoft.Compute/virtualMachines" -> "compute:virtualMachines"
	parts := strings.SplitN(t, "/", 2)
	if len(parts) != 2 {
		return strings.ToLower(t)
	}
	ns := strings.TrimPrefix(parts[0], "Microsoft.")
	return strings.ToLower(ns) + ":" + parts[1]
}

func azureResourceKind(t string) cloud.ResourceKind {
	t = strings.ToLower(t)
	switch {
	case strings.Contains(t, "virtualmachines") || strings.Contains(t, "vmss"):
		return cloud.ResourceCompute
	case strings.Contains(t, "storageaccounts"):
		return cloud.ResourceStorage
	case strings.Contains(t, "sql") || strings.Contains(t, "cosmosdb") || strings.Contains(t, "database"):
		return cloud.ResourceDatabase
	case strings.Contains(t, "virtualnetworks") || strings.Contains(t, "networksecuritygroups") || strings.Contains(t, "publicipaddresses"):
		return cloud.ResourceNetwork
	case strings.Contains(t, "loadbalancers") || strings.Contains(t, "applicationgateways"):
		return cloud.ResourceLoadBalancer
	case strings.Contains(t, "containerservice") || strings.Contains(t, "containerregistry") || strings.Contains(t, "managedclusters"):
		return cloud.ResourceContainer
	case strings.Contains(t, "sites") || strings.Contains(t, "functions"):
		return cloud.ResourceServerless
	case strings.Contains(t, "dnszones") || strings.Contains(t, "dns"):
		return cloud.ResourceDNS
	case strings.Contains(t, "cdn"):
		return cloud.ResourceCDN
	case strings.Contains(t, "redis") || strings.Contains(t, "cache"):
		return cloud.ResourceDatabase
	case strings.Contains(t, "keyvault"):
		return cloud.ResourceOther
	case strings.Contains(t, "servicebus") || strings.Contains(t, "eventhub"):
		return cloud.ResourceOther
	default:
		return cloud.ResourceOther
	}
}
