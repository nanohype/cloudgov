package inventory

import (
	"context"
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// ScanOptions controls inventory scanning behavior.
type ScanOptions struct {
	TypeFilter []string // only include these resource types; empty = all
}

// Scan collects all resources across provided providers.
func Scan(ctx context.Context, providers []cloud.InventoryProvider, opts ScanOptions) ([]cloud.InventoryResource, error) {
	var all []cloud.InventoryResource
	for _, provider := range providers {
		resources, err := provider.ListResources(ctx, opts.TypeFilter)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", provider.Name(), err)
		}
		all = append(all, resources...)
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Provider != all[j].Provider {
			return all[i].Provider < all[j].Provider
		}
		if all[i].Kind != all[j].Kind {
			return all[i].Kind < all[j].Kind
		}
		return all[i].Type < all[j].Type
	})
	return all, nil
}

// Summary holds aggregated inventory counts.
type Summary struct {
	Total     int
	ByKind    map[cloud.ResourceKind]int
	ByType    map[string]int
	ByRegion  map[string]int
}

// Summarize computes aggregate counts from an inventory.
func Summarize(resources []cloud.InventoryResource) Summary {
	s := Summary{
		Total:    len(resources),
		ByKind:   make(map[cloud.ResourceKind]int),
		ByType:   make(map[string]int),
		ByRegion: make(map[string]int),
	}
	for _, r := range resources {
		s.ByKind[r.Kind]++
		s.ByType[r.Type]++
		s.ByRegion[r.Region]++
	}
	return s
}
