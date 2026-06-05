package output

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// CompareTable renders a diff comparison table.
func CompareTable(w io.Writer, result CompareResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("STATUS"),
		headerStyle.Render("DOMAIN"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("DETAIL"),
	)

	for _, f := range result.New {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			critStyle.Render("+NEW"),
			f.Domain, f.Type, truncate(f.ResourceID, 40), truncate(f.Detail, 60),
		)
	}
	for _, f := range result.Resolved {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			greenStyle.Render("-RESOLVED"),
			f.Domain, f.Type, truncate(f.ResourceID, 40), truncate(f.Detail, 60),
		)
	}
	for _, f := range result.Unchanged {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			dimStyle.Render("=UNCHANGED"),
			f.Domain, f.Type, truncate(f.ResourceID, 40), truncate(f.Detail, 60),
		)
	}
	tw.Flush()

	fmt.Fprintf(w, "\n%s new, %s resolved, %s unchanged\n",
		critStyle.Render(fmt.Sprintf("%d", len(result.New))),
		greenStyle.Render(fmt.Sprintf("%d", len(result.Resolved))),
		dimStyle.Render(fmt.Sprintf("%d", len(result.Unchanged))),
	)
}

// CompareResult mirrors compare.DiffResult to avoid import cycle.
type CompareResult struct {
	New       []CompareFindingType
	Resolved  []CompareFindingType
	Unchanged []CompareFindingType
}

// CompareFindingType mirrors compare.NormalizedFinding to avoid import cycle.
type CompareFindingType struct {
	Domain     string
	Provider   string
	Type       string
	ResourceID string
	Detail     string
	Severity   string
}

// NewCompareResult creates a CompareResult from raw data.
func NewCompareResult(newF, resolved, unchanged []CompareFindingType) CompareResult {
	return CompareResult{New: newF, Resolved: resolved, Unchanged: unchanged}
}

// NewCompareFinding creates a CompareFindingType.
func NewCompareFinding(domain, provider, typ, resourceID, detail, severity string) CompareFindingType {
	return CompareFindingType{
		Domain: domain, Provider: provider, Type: typ,
		ResourceID: resourceID, Detail: detail, Severity: severity,
	}
}

type compareReport struct {
	New       []CompareFindingJSONType `json:"new"`
	Resolved  []CompareFindingJSONType `json:"resolved"`
	Unchanged []CompareFindingJSONType `json:"unchanged"`
	Summary   compareSummary           `json:"summary"`
}

// CompareFindingJSONType is a finding for JSON comparison output.
type CompareFindingJSONType struct {
	Domain     string `json:"domain"`
	Provider   string `json:"provider"`
	Type       string `json:"type"`
	ResourceID string `json:"resource_id"`
	Detail     string `json:"detail"`
	Severity   string `json:"severity"`
}

type compareSummary struct {
	New       int `json:"new"`
	Resolved  int `json:"resolved"`
	Unchanged int `json:"unchanged"`
}

// WriteCompare marshals comparison results as JSON to w.
func WriteCompare(w io.Writer, newF, resolved, unchanged []CompareFindingJSONType) error {
	return writeJSON(w, compareReport{
		New:       newF,
		Resolved:  resolved,
		Unchanged: unchanged,
		Summary: compareSummary{
			New:       len(newF),
			Resolved:  len(resolved),
			Unchanged: len(unchanged),
		},
	})
}

// CompareFindingJSON creates a CompareFindingJSONType.
func CompareFindingJSON(domain, provider, typ, resourceID, detail, severity string) CompareFindingJSONType {
	return CompareFindingJSONType{
		Domain: domain, Provider: provider, Type: typ,
		ResourceID: resourceID, Detail: detail, Severity: severity,
	}
}
