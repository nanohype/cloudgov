package gcp

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/container/v1"
	"google.golang.org/api/run/v2"
	"google.golang.org/api/sqladmin/v1beta4"

	"github.com/stxkxs/matlock/internal/cloud"
)

// sqladminAPI is the narrow Cloud SQL Admin surface used by this package.
type sqladminAPI interface {
	ListInstances(ctx context.Context, projectID string) ([]*sqladmin.DatabaseInstance, error)
	GetInstance(ctx context.Context, projectID, name string) (*sqladmin.DatabaseInstance, error)
}

type sqladminAdapter struct{ svc *sqladmin.Service }

func (a *sqladminAdapter) ListInstances(ctx context.Context, projectID string) ([]*sqladmin.DatabaseInstance, error) {
	resp, err := a.svc.Instances.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Items, nil
}

func (a *sqladminAdapter) GetInstance(ctx context.Context, projectID, name string) (*sqladmin.DatabaseInstance, error) {
	return a.svc.Instances.Get(projectID, name).Context(ctx).Do()
}

// containerAPI is the narrow GKE surface used by this package.
type containerAPI interface {
	ListClusters(ctx context.Context, parent string) ([]*container.Cluster, error)
	GetCluster(ctx context.Context, name string) (*container.Cluster, error)
}

type containerAdapter struct{ svc *container.Service }

func (a *containerAdapter) ListClusters(ctx context.Context, parent string) ([]*container.Cluster, error) {
	resp, err := a.svc.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Clusters, nil
}

func (a *containerAdapter) GetCluster(ctx context.Context, name string) (*container.Cluster, error) {
	return a.svc.Projects.Locations.Clusters.Get(name).Context(ctx).Do()
}

// cloudRunV2API is the narrow Cloud Run v2 surface used by this package.
type cloudRunV2API interface {
	ListServices(ctx context.Context, parent string) ([]*run.GoogleCloudRunV2Service, error)
}

type cloudRunV2Adapter struct{ svc *run.Service }

func (a *cloudRunV2Adapter) ListServices(ctx context.Context, parent string) ([]*run.GoogleCloudRunV2Service, error) {
	var out []*run.GoogleCloudRunV2Service
	err := a.svc.Projects.Locations.Services.List(parent).Pages(ctx, func(page *run.GoogleCloudRunV2ListServicesResponse) error {
		out = append(out, page.Services...)
		return nil
	})
	return out, err
}

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

	instancesByZone, err := p.compute.AggregatedInstances(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("list compute instances: %w", err)
	}

	var resources []cloud.InventoryResource
	for zone, instances := range instancesByZone {
		for _, inst := range instances {
			region := zoneToRegion(zone)
			resources = append(resources, cloud.InventoryResource{
				Kind:     cloud.ResourceCompute,
				Type:     "compute:instance",
				ID:       fmt.Sprintf("%d", inst.Id),
				Name:     inst.Name,
				Provider: "gcp",
				Region:   region,
				Tags:     inst.Labels,
				Status:   inst.Status,
			})
		}
	}
	return resources, nil
}

func (p *Provider) listGCSBuckets(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	gcs, err := p.newGCS(ctx)
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	defer gcs.Close()

	buckets, err := gcs.ListBuckets(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var resources []cloud.InventoryResource
	for _, attrs := range buckets {
		created := attrs.Created
		resources = append(resources, cloud.InventoryResource{
			Kind:      cloud.ResourceStorage,
			Type:      "gcs:bucket",
			ID:        attrs.Name,
			Name:      attrs.Name,
			Provider:  "gcp",
			Region:    attrs.Location,
			Tags:      attrs.Labels,
			CreatedAt: &created,
		})
	}
	return resources, nil
}

func (p *Provider) listCloudSQLInstances(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	instances, err := p.sqladmin.ListInstances(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("list cloud sql instances: %w", err)
	}

	var resources []cloud.InventoryResource
	for _, inst := range instances {
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

	parent := "projects/" + p.projectID + "/locations/-"
	clusters, err := p.container.ListClusters(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("list gke clusters: %w", err)
	}

	var resources []cloud.InventoryResource
	for _, c := range clusters {
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

	parent := "projects/" + p.projectID + "/locations/-"
	services, err := p.cloudRunV2.ListServices(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("list cloud run services: %w", err)
	}

	var resources []cloud.InventoryResource
	for _, s := range services {
		name := s.Name
		if parts := strings.Split(name, "/"); len(parts) > 0 {
			name = parts[len(parts)-1]
		}
		region := ""
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
