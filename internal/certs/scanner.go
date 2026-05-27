package certs

import (
	"context"
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls certificate audit behavior.
type ScanOptions struct {
	MinSeverity cloud.Severity
	Days        int // maximum days until expiry to include (0 = no limit)
}

// Scan lists expiring certificates across all provided CertProviders.
func Scan(ctx context.Context, providers []cloud.CertProvider, opts ScanOptions) ([]cloud.CertFinding, error) {
	var all []cloud.CertFinding
	for _, p := range providers {
		findings, err := p.ListCertificates(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.Name(), err)
		}
		for _, f := range findings {
			if opts.Days > 0 && f.DaysLeft > opts.Days && f.Status != cloud.CertExpired {
				continue
			}
			if cloud.SeverityRank(f.Severity) >= cloud.SeverityRank(opts.MinSeverity) {
				all = append(all, f)
			}
		}
	}

	// Sort by days left ascending (most urgent first), then domain
	sort.Slice(all, func(i, j int) bool {
		if all[i].DaysLeft != all[j].DaysLeft {
			return all[i].DaysLeft < all[j].DaysLeft
		}
		return all[i].Domain < all[j].Domain
	})
	return all, nil
}
