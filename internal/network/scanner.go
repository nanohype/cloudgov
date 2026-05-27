package network

import (
	"context"
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls network audit behavior.
type ScanOptions struct {
	MinSeverity cloud.Severity
}

// Scan audits network security across all provided NetworkProviders.
func Scan(ctx context.Context, providers []cloud.NetworkProvider, opts ScanOptions) ([]cloud.NetworkFinding, error) {
	var all []cloud.NetworkFinding
	for _, p := range providers {
		findings, err := p.AuditNetwork(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.Name(), err)
		}
		for _, f := range findings {
			if cloud.SeverityRank(f.Severity) >= cloud.SeverityRank(opts.MinSeverity) {
				all = append(all, f)
			}
		}
	}

	// Sort by severity descending, then resource name
	sort.Slice(all, func(i, j int) bool {
		ri := cloud.SeverityRank(all[i].Severity)
		rj := cloud.SeverityRank(all[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return all[i].Resource < all[j].Resource
	})
	return all, nil
}
