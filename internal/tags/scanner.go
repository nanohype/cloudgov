package tags

import (
	"context"
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls tag audit behavior.
type ScanOptions struct {
	MinSeverity cloud.Severity
	Required    []string
}

// Scan audits resource tags across all provided TagProviders.
func Scan(ctx context.Context, providers []cloud.TagProvider, opts ScanOptions) ([]cloud.TagFinding, error) {
	var all []cloud.TagFinding
	for _, p := range providers {
		findings, err := p.AuditTags(ctx, opts.Required)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.Name(), err)
		}
		for _, f := range findings {
			if cloud.SeverityRank(f.Severity) >= cloud.SeverityRank(opts.MinSeverity) {
				all = append(all, f)
			}
		}
	}

	// Sort by provider, then resource type, then resource ID
	sort.Slice(all, func(i, j int) bool {
		if all[i].Provider != all[j].Provider {
			return all[i].Provider < all[j].Provider
		}
		if all[i].ResourceType != all[j].ResourceType {
			return all[i].ResourceType < all[j].ResourceType
		}
		return all[i].ResourceID < all[j].ResourceID
	})
	return all, nil
}
