package compare

// DiffStatus classifies how a finding changed between two reports.
type DiffStatus string

const (
	DiffNew       DiffStatus = "NEW"
	DiffResolved  DiffStatus = "RESOLVED"
	DiffUnchanged DiffStatus = "UNCHANGED"
)

// DiffEntry is a single finding with its comparison status.
type DiffEntry struct {
	Status  DiffStatus        `json:"status"`
	Finding NormalizedFinding `json:"finding"`
}

// DiffResult holds the full comparison output.
type DiffResult struct {
	New       []NormalizedFinding `json:"new"`
	Resolved  []NormalizedFinding `json:"resolved"`
	Unchanged []NormalizedFinding `json:"unchanged"`
}

// Diff compares baseline and current findings and classifies each.
// Uses MatchKey for O(n+m) comparison.
func Diff(baseline, current []NormalizedFinding) DiffResult {
	baselineMap := make(map[string]NormalizedFinding, len(baseline))
	for _, f := range baseline {
		baselineMap[f.MatchKey()] = f
	}

	currentMap := make(map[string]NormalizedFinding, len(current))
	for _, f := range current {
		currentMap[f.MatchKey()] = f
	}

	var result DiffResult

	// Findings in current but not in baseline = NEW
	// Findings in both = UNCHANGED
	for _, f := range current {
		key := f.MatchKey()
		if _, inBaseline := baselineMap[key]; inBaseline {
			result.Unchanged = append(result.Unchanged, f)
		} else {
			result.New = append(result.New, f)
		}
	}

	// Findings in baseline but not in current = RESOLVED
	for _, f := range baseline {
		key := f.MatchKey()
		if _, inCurrent := currentMap[key]; !inCurrent {
			result.Resolved = append(result.Resolved, f)
		}
	}

	return result
}
