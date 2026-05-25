package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ListOrphans returns unused Azure compute and network resources.
func (p *Provider) ListOrphans(ctx context.Context) ([]cloud.OrphanResource, error) {
	var orphans []cloud.OrphanResource

	disks, err := p.orphanDisks(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan disks: %w", err)
	}
	orphans = append(orphans, disks...)

	ips, err := p.orphanIPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan IPs: %w", err)
	}
	orphans = append(orphans, ips...)

	return orphans, nil
}

func (p *Provider) orphanDisks(ctx context.Context) ([]cloud.OrphanResource, error) {
	client, err := armcompute.NewDisksClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("disks client: %w", err)
	}

	var orphans []cloud.OrphanResource
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list disks page: %w", err)
		}
		for _, disk := range page.Value {
			if disk.Properties == nil {
				continue
			}
			if disk.Properties.DiskState != nil && *disk.Properties.DiskState != armcompute.DiskStateUnattached {
				continue
			}
			sizeGB := int32(0)
			if disk.Properties.DiskSizeGB != nil {
				sizeGB = *disk.Properties.DiskSizeGB
			}
			cost := float64(sizeGB) * 0.05 // ~$0.05/GB-month for Standard_LRS
			name := ""
			if disk.Name != nil {
				name = *disk.Name
			}
			region := ""
			if disk.Location != nil {
				region = *disk.Location
			}
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanDisk,
				ID:          ptrStr(disk.ID),
				Name:        name,
				Region:      region,
				Provider:    "azure",
				MonthlyCost: cost,
				Detail:      fmt.Sprintf("%d GiB unattached managed disk", sizeGB),
			})
		}
	}
	return orphans, nil
}

func (p *Provider) orphanIPs(ctx context.Context) ([]cloud.OrphanResource, error) {
	client, err := armnetwork.NewPublicIPAddressesClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("public IPs client: %w", err)
	}

	var orphans []cloud.OrphanResource
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list public IPs page: %w", err)
		}
		for _, ip := range page.Value {
			if ip.Properties == nil {
				continue
			}
			if ip.Properties.IPConfiguration != nil {
				continue // in use
			}
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanIP,
				ID:          ptrStr(ip.ID),
				Name:        ptrStr(ip.Name),
				Region:      ptrStr(ip.Location),
				Provider:    "azure",
				MonthlyCost: 2.63, // ~$0.0036/hr for static public IP
				Detail:      fmt.Sprintf("public IP %s is not associated with any resource", ptrStr(ip.Properties.IPAddress)),
			})
		}
	}
	return orphans, nil
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
