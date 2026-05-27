package iam

import (
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// BuildMinimalPermissions deduplicates and sorts used permissions.
func BuildMinimalPermissions(used []cloud.Permission) []cloud.Permission {
	seen := make(map[string]bool)
	var out []cloud.Permission
	for _, p := range used {
		key := p.Action + "|" + p.Resource
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Action < out[j].Action
	})
	return out
}

// GroupByResource groups permissions by resource for compact policy statements.
func GroupByResource(perms []cloud.Permission) map[string][]string {
	grouped := make(map[string][]string)
	for _, p := range perms {
		r := p.Resource
		if r == "" {
			r = "*"
		}
		grouped[r] = append(grouped[r], p.Action)
	}
	for r, actions := range grouped {
		seen := make(map[string]bool)
		var deduped []string
		for _, a := range actions {
			if !seen[a] {
				seen[a] = true
				deduped = append(deduped, a)
			}
		}
		sort.Strings(deduped)
		grouped[r] = deduped
	}
	return grouped
}
