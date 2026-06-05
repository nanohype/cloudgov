package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// NetworkFindings renders a network security findings table.
func NetworkFindings(w io.Writer, findings []cloud.NetworkFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("REGION"),
		headerStyle.Render("PORT"),
		headerStyle.Render("CIDR"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Type), f.Provider, f.Resource, f.Region, f.Port, f.CIDR, truncate(f.Detail, 60),
		)
	}
	tw.Flush()
}

type networkReport struct {
	Findings []cloud.NetworkFinding `json:"findings"`
	Total    int                    `json:"total"`
}

// WriteNetwork marshals network findings as JSON to w.
func WriteNetwork(w io.Writer, findings []cloud.NetworkFinding) error {
	return writeJSON(w, networkReport{Findings: findings, Total: len(findings)})
}
