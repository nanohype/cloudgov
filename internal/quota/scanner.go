package quota

import (
	"context"
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls quota scanning behavior.
type ScanOptions struct {
	MinUtilization float64 // only report quotas above this utilization percentage
}

// Scan collects quota usage across all provided providers.
func Scan(ctx context.Context, providers []cloud.QuotaProvider, opts ScanOptions) ([]cloud.QuotaUsage, error) {
	var all []cloud.QuotaUsage
	for _, provider := range providers {
		quotas, err := provider.ListQuotas(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", provider.Name(), err)
		}
		for _, q := range quotas {
			if q.Utilization >= opts.MinUtilization {
				all = append(all, q)
			}
		}
	}

	// Sort by utilization descending
	sort.Slice(all, func(i, j int) bool {
		return all[i].Utilization > all[j].Utilization
	})
	return all, nil
}

// Summary holds aggregated quota counts by severity.
type Summary struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
}

// Summarize counts quotas by severity threshold.
func Summarize(quotas []cloud.QuotaUsage) Summary {
	s := Summary{Total: len(quotas)}
	for _, q := range quotas {
		switch cloud.QuotaSeverity(q.Utilization) {
		case cloud.SeverityCritical:
			s.Critical++
		case cloud.SeverityHigh:
			s.High++
		case cloud.SeverityMedium:
			s.Medium++
		default:
			s.Low++
		}
	}
	return s
}
