package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/compute/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

// computeAPI is the narrow GCP Compute surface used by this package.
// Extend it (do not declare a parallel interface) when other files need
// additional methods.
type computeAPI interface {
	AggregatedDisks(ctx context.Context, projectID, filter string) ([]*compute.Disk, error)
	AggregatedAddresses(ctx context.Context, projectID, filter string) ([]*compute.Address, error)
	AggregatedInstances(ctx context.Context, projectID string) (map[string][]*compute.Instance, error) // zone -> instances
	ListFirewalls(ctx context.Context, projectID string) ([]*compute.Firewall, error)
	GetProject(ctx context.Context, projectID string) (*compute.Project, error)
	GetFirewall(ctx context.Context, projectID, name string) (*compute.Firewall, error)
	GetInstance(ctx context.Context, projectID, zone, name string) (*compute.Instance, error)
}

type computeAdapter struct{ svc *compute.Service }

func (a *computeAdapter) AggregatedDisks(ctx context.Context, projectID, filter string) ([]*compute.Disk, error) {
	var out []*compute.Disk
	call := a.svc.Disks.AggregatedList(projectID)
	if filter != "" {
		call = call.Filter(filter)
	}
	err := call.Pages(ctx, func(page *compute.DiskAggregatedList) error {
		for _, items := range page.Items {
			out = append(out, items.Disks...)
		}
		return nil
	})
	return out, err
}

func (a *computeAdapter) AggregatedAddresses(ctx context.Context, projectID, filter string) ([]*compute.Address, error) {
	var out []*compute.Address
	call := a.svc.Addresses.AggregatedList(projectID)
	if filter != "" {
		call = call.Filter(filter)
	}
	err := call.Pages(ctx, func(page *compute.AddressAggregatedList) error {
		for _, items := range page.Items {
			out = append(out, items.Addresses...)
		}
		return nil
	})
	return out, err
}

func (a *computeAdapter) AggregatedInstances(ctx context.Context, projectID string) (map[string][]*compute.Instance, error) {
	out := make(map[string][]*compute.Instance)
	err := a.svc.Instances.AggregatedList(projectID).Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, items := range page.Items {
			out[zone] = append(out[zone], items.Instances...)
		}
		return nil
	})
	return out, err
}

func (a *computeAdapter) ListFirewalls(ctx context.Context, projectID string) ([]*compute.Firewall, error) {
	var out []*compute.Firewall
	err := a.svc.Firewalls.List(projectID).Pages(ctx, func(page *compute.FirewallList) error {
		out = append(out, page.Items...)
		return nil
	})
	return out, err
}

func (a *computeAdapter) GetProject(ctx context.Context, projectID string) (*compute.Project, error) {
	return a.svc.Projects.Get(projectID).Context(ctx).Do()
}

func (a *computeAdapter) GetFirewall(ctx context.Context, projectID, name string) (*compute.Firewall, error) {
	return a.svc.Firewalls.Get(projectID, name).Context(ctx).Do()
}

func (a *computeAdapter) GetInstance(ctx context.Context, projectID, zone, name string) (*compute.Instance, error) {
	return a.svc.Instances.Get(projectID, zone, name).Context(ctx).Do()
}

// ListOrphans returns unused GCP compute resources.
func (p *Provider) ListOrphans(ctx context.Context) ([]cloud.OrphanResource, error) {
	var orphans []cloud.OrphanResource

	disks, err := p.orphanDisks(ctx)
	if err != nil {
		return nil, err
	}
	orphans = append(orphans, disks...)

	ips, err := p.orphanIPs(ctx)
	if err != nil {
		return nil, err
	}
	orphans = append(orphans, ips...)

	return orphans, nil
}

func (p *Provider) orphanDisks(ctx context.Context) ([]cloud.OrphanResource, error) {
	disks, err := p.compute.AggregatedDisks(ctx, p.projectID, "status=READY")
	if err != nil {
		return nil, fmt.Errorf("list disks: %w", err)
	}
	var orphans []cloud.OrphanResource
	for _, disk := range disks {
		if len(disk.Users) > 0 {
			continue // disk is attached
		}
		cost := float64(disk.SizeGb) * 0.04 // ~$0.04/GB-month for pd-standard
		orphans = append(orphans, cloud.OrphanResource{
			Kind:        cloud.OrphanDisk,
			ID:          fmt.Sprintf("%d", disk.Id),
			Name:        disk.Name,
			Region:      disk.Zone,
			Provider:    "gcp",
			MonthlyCost: cost,
			Detail:      fmt.Sprintf("%d GiB %s, no users", disk.SizeGb, disk.Type),
		})
	}
	return orphans, nil
}

func (p *Provider) orphanIPs(ctx context.Context) ([]cloud.OrphanResource, error) {
	addrs, err := p.compute.AggregatedAddresses(ctx, p.projectID, "status=RESERVED")
	if err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	var orphans []cloud.OrphanResource
	for _, addr := range addrs {
		if len(addr.Users) > 0 {
			continue
		}
		orphans = append(orphans, cloud.OrphanResource{
			Kind:        cloud.OrphanIP,
			ID:          fmt.Sprintf("%d", addr.Id),
			Name:        addr.Address,
			Region:      addr.Region,
			Provider:    "gcp",
			MonthlyCost: 1.46, // ~$0.002/hr for unused static IP
			Detail:      fmt.Sprintf("static IP %s is reserved but unassigned", addr.Address),
		})
	}
	return orphans, nil
}
