package drift

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/sync/errgroup"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls drift scanning behavior.
type ScanOptions struct {
	Concurrency  int
	ResourceType string // filter to a single resource type if non-empty
}

// Scan checks all parsed resources for drift using the provided DriftProviders.
func Scan(ctx context.Context, resources []ParsedResource, providers []cloud.DriftProvider, opts ScanOptions) ([]cloud.DriftResult, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}

	// Build supported-types lookup per provider
	providerByType := make(map[string]cloud.DriftProvider)
	for _, p := range providers {
		for _, rt := range p.SupportedResourceTypes() {
			providerByType[rt] = p
		}
	}

	// Filter resources
	var filtered []ParsedResource
	for _, r := range resources {
		if opts.ResourceType != "" && r.Type != opts.ResourceType {
			continue
		}
		if _, ok := providerByType[r.Type]; !ok {
			continue
		}
		filtered = append(filtered, r)
	}

	results := make([]cloud.DriftResult, len(filtered))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(opts.Concurrency)

	for i, res := range filtered {
		g.Go(func() error {
			provider := providerByType[res.Type]
			result, err := provider.CheckDrift(ctx, res.Type, res.ID, res.Attributes)
			if err != nil {
				results[i] = cloud.DriftResult{
					ResourceType: res.Type,
					ResourceID:   res.ID,
					ResourceName: res.Address,
					Provider:     res.Provider,
					Status:       cloud.DriftError,
					Detail:       fmt.Sprintf("check drift: %v", err),
				}
				return nil
			}
			result.ResourceName = res.Address
			result.Provider = res.Provider
			results[i] = result
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Filter out zero-value results from unused slots
	var final []cloud.DriftResult
	for _, r := range results {
		if r.ResourceType != "" {
			final = append(final, r)
		}
	}

	sort.Slice(final, func(i, j int) bool {
		if final[i].Status != final[j].Status {
			return driftStatusRank(final[i].Status) > driftStatusRank(final[j].Status)
		}
		return final[i].ResourceName < final[j].ResourceName
	})
	return final, nil
}

func driftStatusRank(s cloud.DriftStatus) int {
	switch s {
	case cloud.DriftDeleted:
		return 3
	case cloud.DriftModified:
		return 2
	case cloud.DriftError:
		return 1
	default:
		return 0
	}
}
