package gcp

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/stxkxs/matlock/internal/cloud"
)

// gcsAPI is the narrow GCS surface used by this package. Extend it when
// other files need additional methods.
type gcsAPI interface {
	ListBuckets(ctx context.Context, projectID string) ([]*storage.BucketAttrs, error)
	Close() error
}

type gcsAdapter struct{ client *storage.Client }

func (a *gcsAdapter) ListBuckets(ctx context.Context, projectID string) ([]*storage.BucketAttrs, error) {
	var out []*storage.BucketAttrs
	it := a.client.Buckets(ctx, projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, attrs)
	}
}

func (a *gcsAdapter) Close() error { return a.client.Close() }

// AuditStorage checks GCS buckets for public access and encryption settings.
func (p *Provider) AuditStorage(ctx context.Context) ([]cloud.BucketFinding, error) {
	gcs, err := p.newGCS(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	defer gcs.Close()

	buckets, err := gcs.ListBuckets(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var findings []cloud.BucketFinding
	for _, attrs := range buckets {
		findings = append(findings, p.checkGCSPublicAccess(attrs)...)
		findings = append(findings, p.checkGCSVersioning(attrs)...)
		findings = append(findings, p.checkGCSLogging(attrs)...)
	}
	return findings, nil
}

func (p *Provider) checkGCSPublicAccess(attrs *storage.BucketAttrs) []cloud.BucketFinding {
	if attrs.PublicAccessPrevention == storage.PublicAccessPreventionEnforced {
		return nil
	}
	// Check ACL for allUsers or allAuthenticatedUsers
	for _, acl := range attrs.ACL {
		if acl.Entity == storage.AllUsers || acl.Entity == storage.AllAuthenticatedUsers {
			return []cloud.BucketFinding{{
				Severity:    cloud.SeverityCritical,
				Type:        cloud.BucketPublicAccess,
				Provider:    "gcp",
				Bucket:      attrs.Name,
				Region:      attrs.Location,
				Detail:      fmt.Sprintf("bucket grants public access to %s", acl.Entity),
				Remediation: fmt.Sprintf("gsutil iam ch -d allUsers gs://%s", attrs.Name),
			}}
		}
	}
	return nil
}

func (p *Provider) checkGCSVersioning(attrs *storage.BucketAttrs) []cloud.BucketFinding {
	if attrs.VersioningEnabled {
		return nil
	}
	return []cloud.BucketFinding{{
		Severity:    cloud.SeverityMedium,
		Type:        cloud.BucketNoVersioning,
		Provider:    "gcp",
		Bucket:      attrs.Name,
		Region:      attrs.Location,
		Detail:      "object versioning is not enabled",
		Remediation: fmt.Sprintf("gsutil versioning set on gs://%s", attrs.Name),
	}}
}

func (p *Provider) checkGCSLogging(attrs *storage.BucketAttrs) []cloud.BucketFinding {
	if attrs.Logging != nil && attrs.Logging.LogBucket != "" {
		return nil
	}
	return []cloud.BucketFinding{{
		Severity:    cloud.SeverityLow,
		Type:        cloud.BucketNoLogging,
		Provider:    "gcp",
		Bucket:      attrs.Name,
		Region:      attrs.Location,
		Detail:      "access logging is not enabled",
		Remediation: fmt.Sprintf("gsutil logging set on -b gs://<log-bucket> gs://%s", attrs.Name),
	}}
}
