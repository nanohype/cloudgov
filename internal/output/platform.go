package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// PlatformFindings renders Platform-tenant conformance findings to w.
func PlatformFindings(w io.Writer, findings []cloud.PlatformFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no platform conformance findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("PLATFORM"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			sev, f.Platform, string(f.Type), f.Resource, truncate(f.Detail, 70),
		)
	}
	tw.Flush()
}

type platformReport struct {
	Findings []cloud.PlatformFinding `json:"findings"`
	Total    int                     `json:"total"`
}

// WritePlatform marshals Platform conformance findings as JSON to w.
func WritePlatform(w io.Writer, findings []cloud.PlatformFinding) error {
	return writeJSON(w, platformReport{Findings: findings, Total: len(findings)})
}
