package cost

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls cost diff behavior.
type ScanOptions struct {
	Days        int    // "after" period = last N days; "before" = the N days prior
	MinSeverity cloud.Severity
	Threshold   float64 // only include entries with abs(PctChange) > Threshold; 0 means no filter
}

// Scan fetches cost diffs from all provided CostProviders and merges them.
func Scan(ctx context.Context, providers []cloud.CostProvider, opts ScanOptions) ([]cloud.CostDiff, error) {
	now := time.Now().UTC().Truncate(24 * time.Hour)
	afterEnd := now
	afterStart := now.AddDate(0, 0, -opts.Days)
	beforeEnd := afterStart
	beforeStart := beforeEnd.AddDate(0, 0, -opts.Days)

	var diffs []cloud.CostDiff
	for _, provider := range providers {
		diff, err := provider.GetCostDiff(ctx, beforeStart, beforeEnd, afterStart, afterEnd)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", provider.Name(), err)
		}
		// Sort entries by absolute delta descending
		sort.Slice(diff.Entries, func(i, j int) bool {
			ai := diff.Entries[i].Delta
			if ai < 0 {
				ai = -ai
			}
			aj := diff.Entries[j].Delta
			if aj < 0 {
				aj = -aj
			}
			return ai > aj
		})
		if opts.Threshold > 0 {
			filtered := diff.Entries[:0]
			for _, e := range diff.Entries {
				if math.Abs(e.PctChange) > opts.Threshold {
					filtered = append(filtered, e)
				}
			}
			diff.Entries = filtered
		}
		diffs = append(diffs, diff)
	}
	return diffs, nil
}
