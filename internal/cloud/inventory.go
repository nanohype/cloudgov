package cloud

import (
	"context"
	"time"
)

// ResourceKind classifies the type of cloud resource.
type ResourceKind string

const (
	ResourceCompute      ResourceKind = "compute"
	ResourceDatabase     ResourceKind = "database"
	ResourceStorage      ResourceKind = "storage"
	ResourceNetwork      ResourceKind = "network"
	ResourceLoadBalancer ResourceKind = "load_balancer"
	ResourceContainer    ResourceKind = "container"
	ResourceServerless   ResourceKind = "serverless"
	ResourceIAM          ResourceKind = "iam"
	ResourceDNS          ResourceKind = "dns"
	ResourceCDN          ResourceKind = "cdn"
	ResourceOther        ResourceKind = "other"
)

// InventoryResource represents a single cloud resource in the inventory.
type InventoryResource struct {
	Kind         ResourceKind      `json:"kind"`
	Type         string            `json:"type"`     // e.g. "ec2:instance", "s3:bucket", "rds:instance"
	ID           string            `json:"id"`       // resource ID / ARN
	Name         string            `json:"name"`     // display name
	Provider     string            `json:"provider"` // "aws" | "gcp" | "azure"
	Region       string            `json:"region"`
	Tags         map[string]string `json:"tags,omitempty"`
	CreatedAt    *time.Time        `json:"created_at,omitempty"`
	Status       string            `json:"status,omitempty"` // "running", "stopped", "available", etc.
}

// InventoryProvider lists cloud resources for inventory.
type InventoryProvider interface {
	Provider
	ListResources(ctx context.Context, typeFilter []string) ([]InventoryResource, error)
}
