package cloud

import "context"

// DriftStatus describes the state of a resource relative to its Terraform state.
type DriftStatus string

const (
	DriftInSync   DriftStatus = "IN_SYNC"
	DriftModified DriftStatus = "MODIFIED"
	DriftDeleted  DriftStatus = "DELETED"
	DriftError    DriftStatus = "ERROR"
)

// DriftField describes a single attribute that has drifted.
type DriftField struct {
	Field    string `json:"field"`    // "ingress.0.cidr_blocks"
	Expected string `json:"expected"` // value from tfstate
	Actual   string `json:"actual"`   // value from cloud API
}

// DriftResult is the outcome of checking a single resource for drift.
type DriftResult struct {
	ResourceType string       `json:"resource_type"` // "aws_security_group"
	ResourceID   string       `json:"resource_id"`   // actual cloud ID
	ResourceName string       `json:"resource_name"` // terraform address: "aws_security_group.web"
	Provider     string       `json:"provider"`
	Status       DriftStatus  `json:"status"`
	Fields       []DriftField `json:"fields,omitempty"`
	Detail       string       `json:"detail,omitempty"`
}

// DriftProvider checks live cloud state against Terraform state attributes.
type DriftProvider interface {
	Provider
	CheckDrift(ctx context.Context, resourceType, resourceID string, attrs map[string]interface{}) (DriftResult, error)
	SupportedResourceTypes() []string
}
