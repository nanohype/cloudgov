package gcp

import (
	"context"
	"fmt"
	"strings"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/sqladmin/v1beta4"
	cstorage "google.golang.org/api/storage/v1"

	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/drift"
)

// SupportedResourceTypes returns the Terraform resource types this provider can check for drift.
func (p *Provider) SupportedResourceTypes() []string {
	return []string{
		"google_compute_firewall",
		"google_storage_bucket",
		"google_compute_instance",
		"google_sql_database_instance",
		"google_container_cluster",
	}
}

// CheckDrift compares live GCP state against the provided Terraform attributes.
func (p *Provider) CheckDrift(ctx context.Context, resourceType, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	switch resourceType {
	case "google_compute_firewall":
		return p.checkFirewallDrift(ctx, resourceID, attrs)
	case "google_storage_bucket":
		return p.checkStorageBucketDrift(ctx, resourceID, attrs)
	case "google_compute_instance":
		return p.checkComputeInstanceDrift(ctx, resourceID, attrs)
	case "google_sql_database_instance":
		return p.checkSQLInstanceDrift(ctx, resourceID, attrs)
	case "google_container_cluster":
		return p.checkGKEClusterDrift(ctx, resourceID, attrs)
	default:
		return cloud.DriftResult{
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "unsupported resource type",
		}, nil
	}
}

func (p *Provider) checkFirewallDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create compute client: %w", err)
	}

	// Extract firewall name from ID (projects/proj/global/firewalls/name or just name)
	name := resourceID
	if parts := strings.Split(resourceID, "/"); len(parts) > 0 {
		name = parts[len(parts)-1]
	}

	fw, err := svc.Firewalls.Get(p.projectID, name).Context(ctx).Do()
	if err != nil {
		if isGoogleNotFound(err) {
			return cloud.DriftResult{
				ResourceType: "google_compute_firewall",
				ResourceID:   resourceID,
				Status:       cloud.DriftDeleted,
				Detail:       "firewall rule not found in GCP",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get firewall %s: %w", name, err)
	}

	actual := map[string]interface{}{
		"name":        fw.Name,
		"description": fw.Description,
		"direction":   fw.Direction,
		"disabled":    fmt.Sprintf("%v", fw.Disabled),
		"priority":    fmt.Sprintf("%d", fw.Priority),
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "description", "direction", "disabled", "priority"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "google_compute_firewall",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "google_compute_firewall",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkStorageBucketDrift(ctx context.Context, bucketName string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	svc, err := cstorage.NewService(ctx, p.opts...)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create storage client: %w", err)
	}

	bucket, err := svc.Buckets.Get(bucketName).Context(ctx).Do()
	if err != nil {
		if isGoogleNotFound(err) {
			return cloud.DriftResult{
				ResourceType: "google_storage_bucket",
				ResourceID:   bucketName,
				Status:       cloud.DriftDeleted,
				Detail:       "storage bucket not found in GCP",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get bucket %s: %w", bucketName, err)
	}

	actual := map[string]interface{}{
		"name":          bucket.Name,
		"location":      strings.ToLower(bucket.Location),
		"storage_class": bucket.StorageClass,
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "location", "storage_class"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "google_storage_bucket",
			ResourceID:   bucketName,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "google_storage_bucket",
		ResourceID:   bucketName,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkComputeInstanceDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create compute client: %w", err)
	}

	// Extract zone and name from resourceID or attrs
	zone := ""
	name := resourceID
	if z, ok := attrs["zone"]; ok {
		if s, ok := z.(string); ok {
			zone = s
			// Strip projects/P/zones/Z prefix if present
			if parts := strings.Split(zone, "/"); len(parts) > 0 {
				zone = parts[len(parts)-1]
			}
		}
	}
	if parts := strings.Split(resourceID, "/"); len(parts) > 0 {
		name = parts[len(parts)-1]
	}
	if zone == "" {
		return cloud.DriftResult{
			ResourceType: "google_compute_instance",
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "cannot determine zone from attributes",
		}, nil
	}

	inst, err := svc.Instances.Get(p.projectID, zone, name).Context(ctx).Do()
	if err != nil {
		if isGoogleNotFound(err) {
			return cloud.DriftResult{
				ResourceType: "google_compute_instance",
				ResourceID:   resourceID,
				Status:       cloud.DriftDeleted,
				Detail:       "compute instance not found in GCP",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get instance %s: %w", name, err)
	}

	// Extract machine type short name from full URL
	machineType := inst.MachineType
	if parts := strings.Split(machineType, "/"); len(parts) > 0 {
		machineType = parts[len(parts)-1]
	}

	actual := map[string]interface{}{
		"machine_type": machineType,
		"name":         inst.Name,
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"machine_type", "name"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "google_compute_instance",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "google_compute_instance",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkSQLInstanceDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	svc, err := sqladmin.NewService(ctx, p.opts...)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create sqladmin client: %w", err)
	}

	name := resourceID
	if parts := strings.Split(resourceID, "/"); len(parts) > 0 {
		name = parts[len(parts)-1]
	}

	inst, err := svc.Instances.Get(p.projectID, name).Context(ctx).Do()
	if err != nil {
		if isGoogleNotFound(err) {
			return cloud.DriftResult{
				ResourceType: "google_sql_database_instance",
				ResourceID:   resourceID,
				Status:       cloud.DriftDeleted,
				Detail:       "Cloud SQL instance not found in GCP",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get sql instance %s: %w", name, err)
	}

	actual := map[string]interface{}{
		"database_version": inst.DatabaseVersion,
	}
	if inst.Settings != nil {
		actual["tier"] = inst.Settings.Tier
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"database_version", "tier"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "google_sql_database_instance",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "google_sql_database_instance",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkGKEClusterDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	svc, err := container.NewService(ctx, p.opts...)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create container client: %w", err)
	}

	// Extract location and name from resourceID or attrs
	location := ""
	name := resourceID
	if loc, ok := attrs["location"]; ok {
		if s, ok := loc.(string); ok {
			location = s
		}
	}
	if parts := strings.Split(resourceID, "/"); len(parts) > 0 {
		name = parts[len(parts)-1]
	}
	if location == "" {
		return cloud.DriftResult{
			ResourceType: "google_container_cluster",
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "cannot determine location from attributes",
		}, nil
	}

	parent := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", p.projectID, location, name)
	cluster, err := svc.Projects.Locations.Clusters.Get(parent).Context(ctx).Do()
	if err != nil {
		if isGoogleNotFound(err) {
			return cloud.DriftResult{
				ResourceType: "google_container_cluster",
				ResourceID:   resourceID,
				Status:       cloud.DriftDeleted,
				Detail:       "GKE cluster not found in GCP",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get cluster %s: %w", name, err)
	}

	actual := map[string]interface{}{
		"name":               cluster.Name,
		"min_master_version": cluster.CurrentMasterVersion,
		"node_version":       cluster.CurrentNodeVersion,
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "min_master_version", "node_version"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "google_container_cluster",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "google_container_cluster",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func isGoogleNotFound(err error) bool {
	if gErr, ok := err.(*googleapi.Error); ok {
		return gErr.Code == 404
	}
	return false
}
