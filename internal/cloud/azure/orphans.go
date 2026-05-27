package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/stxkxs/matlock/internal/cloud"
)

// disksAPI is the narrow Compute Disks surface used by this package.
type disksAPI interface {
	List(ctx context.Context) ([]*armcompute.Disk, error)
}

type disksAdapter struct{ client *armcompute.DisksClient }

func (a *disksAdapter) List(ctx context.Context) ([]*armcompute.Disk, error) {
	var out []*armcompute.Disk
	pager := a.client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// publicIPsAPI is the narrow Public IP Addresses surface used here.
type publicIPsAPI interface {
	ListAll(ctx context.Context) ([]*armnetwork.PublicIPAddress, error)
}

type publicIPsAdapter struct {
	client *armnetwork.PublicIPAddressesClient
}

func (a *publicIPsAdapter) ListAll(ctx context.Context) ([]*armnetwork.PublicIPAddress, error) {
	var out []*armnetwork.PublicIPAddress
	pager := a.client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

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
	disks, err := p.disks.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list disks: %w", err)
	}

	var orphans []cloud.OrphanResource
	for _, disk := range disks {
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
	return orphans, nil
}

func (p *Provider) orphanIPs(ctx context.Context) ([]cloud.OrphanResource, error) {
	ips, err := p.publicIPs.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("list public IPs: %w", err)
	}

	var orphans []cloud.OrphanResource
	for _, ip := range ips {
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
	return orphans, nil
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
