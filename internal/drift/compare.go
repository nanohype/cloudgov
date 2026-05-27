package drift

import (
	"fmt"
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// CompareAttributes compares expected attributes (from tfstate) against actual
// attributes (from cloud API) for the given fields. Returns drift fields for
// any differences found.
func CompareAttributes(expected, actual map[string]interface{}, fields []string) []cloud.DriftField {
	var diffs []cloud.DriftField
	for _, field := range fields {
		ev := formatValue(expected[field])
		av := formatValue(actual[field])
		if ev != av {
			diffs = append(diffs, cloud.DriftField{
				Field:    field,
				Expected: ev,
				Actual:   av,
			})
		}
	}
	return diffs
}

// StringMapKeys returns sorted keys from a map[string]interface{}.
func StringMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatValue(v interface{}) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%v", v)
}
