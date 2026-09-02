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
		unknownStyle.Render(fmt.Sprintf("%d", report.Summary.NotEvaluated)),
		report.Summary.Total,
	)
	fmt.Fprintln(w, summary)
}

// WriteCompliance marshals a compliance report as JSON to w.
//
// The incomplete record is normalized here like every other envelope's. A
// benchmark verdict is only as complete as the scans behind it, and this is the
// surface where the difference matters most: the output is the artifact someone
// points at to say a control passed. `null` and an omitted key are the same
// ambiguity — neither can be told apart from a tool that does not report its own
// coverage — so a run whose inputs were whole says so with `[]`.
func WriteCompliance(w io.Writer, report compliance.ComplianceReport) error {
	report.Incomplete = observed(report.Incomplete)
	return writeJSON(w, report)
}
