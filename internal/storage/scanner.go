package storage

import (
	"context"
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls storage audit behavior.
type ScanOptions struct {
	MinSeverity cloud.Severity
}

// Scan audits storage across all provided StorageProviders.
func Scan(ctx context.Context, providers []cloud.StorageProvider, opts ScanOptions) ([]cloud.BucketFinding, error) {
	var all []cloud.BucketFinding
	for _, provider := range providers {
		findings, err := provider.AuditStorage(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", provider.Name(), err)
		}
		for _, f := range findings {
			if cloud.SeverityRank(f.Severity) >= cloud.SeverityRank(opts.MinSeverity) {
				all = append(all, f)
			}
		}
	}

	// Sort by severity descending, then bucket name
	sort.Slice(all, func(i, j int) bool {
		ri := cloud.SeverityRank(all[i].Severity)
		rj := cloud.SeverityRank(all[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return all[i].Bucket < all[j].Bucket
	})
	return all, nil
}
