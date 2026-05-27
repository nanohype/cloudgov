package cloud

import "context"

// BucketFindingType classifies a storage security finding.
type BucketFindingType string

const (
	BucketPublicAccess BucketFindingType = "PUBLIC_ACCESS"
	BucketUnencrypted  BucketFindingType = "UNENCRYPTED"
	BucketNoVersioning BucketFindingType = "NO_VERSIONING"
	BucketNoLogging    BucketFindingType = "NO_LOGGING"
	BucketPublicACL    BucketFindingType = "PUBLIC_ACL"
)

// BucketFinding is a single storage security observation.
type BucketFinding struct {
	Severity    Severity
	Type        BucketFindingType
	Provider    string
	Bucket      string
	Region      string
	Detail      string
	Remediation string
}

// StorageProvider audits object storage buckets.
type StorageProvider interface {
	Provider
	AuditStorage(ctx context.Context) ([]BucketFinding, error)
}
