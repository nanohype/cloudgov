package gcp

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/api/run/v2"
	"google.golang.org/api/sqladmin/v1beta4"

	"github.com/stxkxs/matlock/internal/cloud"
)

// ListResources lists GCP resources for inventory.
func (p *Provider) ListResources(ctx context.Context, typeFilter []string) ([]cloud.InventoryResource, error) {
	filter := make(map[string]bool)
	for _, t := range typeFilter {
		filter[strings.ToLower(t)] = true
	}
	all := len(filter) == 0

	var resources []cloud.InventoryResource

	if all || filter["compute"] || filter["compute:instance"] {
		r, err := p.listComputeInstances(ctx)
		if err != nil {
			return nil, fmt.Errorf("list compute instances: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["gcs"] || filter["gcs:bucket"] {
		r, err := p.listGCSBuckets(ctx)
		if err != nil {
			return nil, fmt.Errorf("list gcs buckets: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["cloudsql"] || filter["cloudsql:instance"] {
		r, err := p.listCloudSQLInstances(ctx)
		if err != nil {
			return nil, fmt.Errorf("list cloud sql instances: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["gke"] || filter["gke:cluster"] {
		r, err := p.listGKEClusters(ctx)
		if err != nil {
			return nil, fmt.Errorf("list gke clusters: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["cloudrun"] || filter["cloudrun:service"] {
		r, err := p.listCloudRunServices(ctx)
		if err != nil {
			return nil, fmt.Errorf("list cloud run services: %w", err)
		}
		resources = append(resources, r...)
	}

	return resources, nil
}

func (p *Provider) listComputeInstances(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create compute service: %w", err)
	}

	var resources []cloud.InventoryResource
	req := svc.Instances.AggregatedList(p.projectID)
	if err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, list := range page.Items {
			for _, inst := range list.Instances {
				region := zoneToRegion(zone)
				labels := inst.Labels
				resources = append(resources, cloud.InventoryResource{
					Kind:     cloud.ResourceCompute,
					Type:     "compute:instance",
					ID:       fmt.Sprintf("%d", inst.Id),
					Name:     inst.Name,
					Provider: "gcp",
					Region:   region,
					Tags:     labels,
					Status:   inst.Status,
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("list compute instances: %w", err)
	}

	return resources, nil
}

func (p *Provider) listGCSBuckets(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	var opts []option.ClientOption
	opts = append(opts, p.opts...)
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	defer client.Close()

	var resources []cloud.InventoryResource
	it := client.Buckets(ctx, p.projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return resources, fmt.Errorf("list buckets: %w", err)
		}
		created := attrs.Created
		r := cloud.InventoryResource{
			Kind:      cloud.ResourceStorage,
			Type:      "gcs:bucket",
			ID:        attrs.Name,
			Name:      attrs.Name,
			Provider:  "gcp",
			Region:    attrs.Location,
			Tags:      attrs.Labels,
			CreatedAt: &created,
		}
		resources = append(resources, r)
	}
	return resources, nil
}

func (p *Provider) listCloudSQLInstances(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	svc, err := sqladmin.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create sqladmin service: %w", err)
	}

	var resources []cloud.InventoryResource
	resp, err := svc.Instances.List(p.projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list cloud sql instances: %w", err)
	}
	for _, inst := range resp.Items {
		resources = append(resources, cloud.InventoryResource{
			Kind:     cloud.ResourceDatabase,
			Type:     "cloudsql:instance",
			ID:       inst.SelfLink,
			Name:     inst.Name,
			Provider: "gcp",
			Region:   inst.Region,
			Status:   inst.State,
		})
	}
	return resources, nil
}

func (p *Provider) listGKEClusters(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	svc, err := container.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create container service: %w", err)
	}

	var resources []cloud.InventoryResource
	parent := "projects/" + p.projectID + "/locations/-"
	resp, err := svc.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list gke clusters: %w", err)
	}
	for _, c := range resp.Clusters {
		resources = append(resources, cloud.InventoryResource{
			Kind:     cloud.ResourceContainer,
			Type:     "gke:cluster",
			ID:       c.SelfLink,
			Name:     c.Name,
			Provider: "gcp",
			Region:   c.Location,
			Status:   c.Status,
		})
	}
	return resources, nil
}

func (p *Provider) listCloudRunServices(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	svc, err := run.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create cloud run service: %w", err)
	}

	var resources []cloud.InventoryResource
	parent := "projects/" + p.projectID + "/locations/-"
	if err := svc.Projects.Locations.Services.List(parent).Pages(ctx, func(page *run.GoogleCloudRunV2ListServicesResponse) error {
		for _, s := range page.Services {
			name := s.Name
			// Extract short name from full resource name
			if parts := strings.Split(name, "/"); len(parts) > 0 {
				name = parts[len(parts)-1]
			}
			region := ""
			// Extract region from full name: projects/P/locations/R/services/S
			if parts := strings.Split(s.Name, "/"); len(parts) >= 4 {
				region = parts[3]
			}
			resources = append(resources, cloud.InventoryResource{
				Kind:     cloud.ResourceServerless,
				Type:     "cloudrun:service",
				ID:       s.Uri,
				Name:     name,
				Provider: "gcp",
				Region:   region,
			})
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("list cloud run services: %w", err)
	}
	return resources, nil
}

func zoneToRegion(zone string) string {
	// "zones/us-central1-a" -> "us-central1"
	zone = strings.TrimPrefix(zone, "zones/")
	parts := strings.Split(zone, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return zone
}
