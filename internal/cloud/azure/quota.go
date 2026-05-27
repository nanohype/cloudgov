package azure

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/stxkxs/matlock/internal/cloud"
)

// computeUsageAPI is the narrow Compute Usage surface used by this package.
type computeUsageAPI interface {
	List(ctx context.Context, location string) ([]*armcompute.Usage, error)
}

type computeUsageAdapter struct{ client *armcompute.UsageClient }

func (a *computeUsageAdapter) List(ctx context.Context, location string) ([]*armcompute.Usage, error) {
	var out []*armcompute.Usage
	pager := a.client.NewListPager(location, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// networkUsageAPI is the narrow Network Usage surface used by this package.
type networkUsageAPI interface {
	List(ctx context.Context, location string) ([]*armnetwork.Usage, error)
}

type networkUsageAdapter struct{ client *armnetwork.UsagesClient }

func (a *networkUsageAdapter) List(ctx context.Context, location string) ([]*armnetwork.Usage, error) {
	var out []*armnetwork.Usage
	pager := a.client.NewListPager(location, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// ListQuotas returns compute, network, and storage quota utilization.
func (p *Provider) ListQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	location := os.Getenv("AZURE_DEFAULTS_LOCATION")
	if location == "" {
		location = "eastus"
	}

	var quotas []cloud.QuotaUsage

	computeQuotas, err := p.computeQuotas(ctx, location)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: azure compute quotas: %v\n", err)
	} else {
		quotas = append(quotas, computeQuotas...)
	}

	networkQuotas, err := p.networkQuotas(ctx, location)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: azure network quotas: %v\n", err)
	} else {
		quotas = append(quotas, networkQuotas...)
	}

	storageQuotas, err := p.storageQuotas(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: azure storage quotas: %v\n", err)
	} else {
		quotas = append(quotas, storageQuotas...)
	}

	return quotas, nil
}

func (p *Provider) computeQuotas(ctx context.Context, location string) ([]cloud.QuotaUsage, error) {
	usages, err := p.computeUsage.List(ctx, location)
	if err != nil {
		return nil, fmt.Errorf("list compute usage: %w", err)
	}

	var quotas []cloud.QuotaUsage
	for _, u := range usages {
		if u.Limit == nil || *u.Limit == 0 {
			continue
		}
		used := float64(int32PtrVal(u.CurrentValue))
		limit := float64(*u.Limit)
		name := ""
		if u.Name != nil && u.Name.LocalizedValue != nil {
			name = *u.Name.LocalizedValue
		}
		quotas = append(quotas, cloud.QuotaUsage{
			Provider:    "azure",
			Service:     "Compute",
			QuotaName:   name,
			Used:        used,
			Limit:       limit,
			Utilization: pctAzure(used, limit),
			Region:      location,
		})
	}
	return quotas, nil
}

func (p *Provider) networkQuotas(ctx context.Context, location string) ([]cloud.QuotaUsage, error) {
	usages, err := p.networkUsage.List(ctx, location)
	if err != nil {
		return nil, fmt.Errorf("list network usage: %w", err)
	}

	var quotas []cloud.QuotaUsage
	for _, u := range usages {
		if u.Limit == nil || *u.Limit == 0 {
			continue
		}
		used := float64(int64PtrVal(u.CurrentValue))
		limit := float64(*u.Limit)
		name := ""
		if u.Name != nil && u.Name.LocalizedValue != nil {
			name = *u.Name.LocalizedValue
		}
		quotas = append(quotas, cloud.QuotaUsage{
			Provider:    "azure",
			Service:     "Network",
			QuotaName:   name,
			Used:        used,
			Limit:       limit,
			Utilization: pctAzure(used, limit),
			Region:      location,
		})
	}
	return quotas, nil
}

func (p *Provider) storageQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	accounts, err := p.storageAccounts.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list storage accounts: %w", err)
	}
	count := len(accounts)

	used := float64(count)
	limit := float64(250) // Default Azure storage account limit per subscription

	return []cloud.QuotaUsage{{
		Provider:    "azure",
		Service:     "Storage",
		QuotaName:   "Storage Accounts",
		Used:        used,
		Limit:       limit,
		Utilization: pctAzure(used, limit),
		Region:      "subscription",
	}}, nil
}

func pctAzure(used, limit float64) float64 {
	if limit == 0 {
		return 0
	}
	return used / limit * 100
}

func int32PtrVal(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}

func int64PtrVal(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// compile-time check
var _ cloud.QuotaProvider = (*Provider)(nil)
