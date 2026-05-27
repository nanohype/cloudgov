package secrets

import (
	"context"
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls secret scanning behavior.
type ScanOptions struct {
	MinSeverity cloud.Severity
}

// ScanProviders scans all provided SecretsProviders for leaked credentials.
func ScanProviders(ctx context.Context, providers []cloud.SecretsProvider, opts ScanOptions) ([]cloud.SecretFinding, error) {
	var all []cloud.SecretFinding
	for _, provider := range providers {
		findings, err := provider.ScanSecrets(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", provider.Name(), err)
		}
		for _, f := range findings {
			if cloud.SeverityRank(f.Severity) >= cloud.SeverityRank(opts.MinSeverity) {
				all = append(all, f)
			}
		}
	}

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
