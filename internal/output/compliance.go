package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/compliance"
)

// ComplianceReport renders a compliance evaluation table.
func ComplianceReport(w io.Writer, report compliance.ComplianceReport) {
	if len(report.Results) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no controls evaluated"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("STATUS"),
		headerStyle.Render("ID"),
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TITLE"),
		headerStyle.Render("DETAIL"),
	)
	for _, r := range report.Results {
		var statusStyled string
		switch r.Status {
		case compliance.StatusPass:
			statusStyled = greenStyle.Render("PASS")
		case compliance.StatusFail:
			statusStyled = critStyle.Render("FAIL")
		default:
			statusStyled = dimStyle.Render("N/A")
		}
		sev := colorSeverity(r.Control.Severity).Render(string(r.Control.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			statusStyled, r.Control.ID, sev, truncate(r.Control.Title, 55), truncate(r.Detail, 50),
		)
	}
	tw.Flush()

	summary := fmt.Sprintf("\n%s passed, %s failed, %s not evaluated (%d total)",
		greenStyle.Render(fmt.Sprintf("%d", report.Summary.Passed)),
		critStyle.Render(fmt.Sprintf("%d", report.Summary.Failed)),
		dimStyle.Render(fmt.Sprintf("%d", report.Summary.NotEvaluated)),
		report.Summary.Total,
	)
	fmt.Fprintln(w, summary)
}

// WriteCompliance marshals a compliance report as JSON to w.
func WriteCompliance(w io.Writer, report compliance.ComplianceReport) error {
	return writeJSON(w, report)
}
