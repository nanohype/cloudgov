package orphans

import (
	"context"
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls orphan scanning behavior.
type ScanOptions struct {
	MinMonthlyCost float64 // only report orphans above this cost threshold
}

// Scan collects orphaned resources across all provided providers.
func Scan(ctx context.Context, providers []cloud.OrphansProvider, opts ScanOptions) ([]cloud.OrphanResource, error) {
	var all []cloud.OrphanResource
	for _, provider := range providers {
		orphans, err := provider.ListOrphans(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", provider.Name(), err)
		}
		for _, o := range orphans {
			// Cluster residue is always reported: it's a conflict/correctness
			// problem (a stale resource blocking re-creation), so its ~$0 cost
			// must not let --min-cost hide it.
			if o.Kind.AlwaysReport() || o.MonthlyCost >= opts.MinMonthlyCost {
				all = append(all, o)
			}
		}
	}

	// Sort by monthly cost descending
	sort.Slice(all, func(i, j int) bool {
		return all[i].MonthlyCost > all[j].MonthlyCost
	})
	return all, nil
}

// TotalMonthlyCost sums the estimated monthly cost of all orphans.
func TotalMonthlyCost(orphans []cloud.OrphanResource) float64 {
	var total float64
	for _, o := range orphans {
		total += o.MonthlyCost
	}
	return total
}
