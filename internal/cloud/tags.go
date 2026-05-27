package cloud

import "context"

// TagFinding is a single resource missing required tags observation.
type TagFinding struct {
	Severity     Severity
	Provider     string
	ResourceID   string
	ResourceType string // "ec2:instance", "s3:bucket", "rds:db", etc.
	Region       string
	MissingTags  []string
	Detail       string
}

// TagProvider audits resources for missing required tags/labels.
type TagProvider interface {
	Provider
	AuditTags(ctx context.Context, required []string) ([]TagFinding, error)
}
