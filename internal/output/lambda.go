package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// LambdaPolicyFindings renders a Lambda resource-policy findings table.
func LambdaPolicyFindings(w io.Writer, findings []cloud.LambdaPolicyFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("FUNCTION"),
		headerStyle.Render("STATEMENT"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Type), f.FunctionName, f.StatementID, truncate(f.Detail, 70),
		)
	}
	tw.Flush()

	var crit, high, med int
	for _, f := range findings {
		switch f.Severity {
		case cloud.SeverityCritical:
			crit++
		case cloud.SeverityHigh:
			high++
		case cloud.SeverityMedium:
			med++
		}
	}
	fmt.Fprintf(w, "\n%s critical, %s high, %s medium\n",
		critStyle.Render(fmt.Sprintf("%d", crit)),
		highStyle.Render(fmt.Sprintf("%d", high)),
		medStyle.Render(fmt.Sprintf("%d", med)),
	)
}

type lambdaPolicyReport struct {
	Findings []cloud.LambdaPolicyFinding `json:"findings"`
	Total    int                         `json:"total"`
}

// WriteLambdaPolicy marshals Lambda resource-policy findings as JSON to w.
func WriteLambdaPolicy(w io.Writer, findings []cloud.LambdaPolicyFinding) error {
	return writeJSON(w, lambdaPolicyReport{Findings: findings, Total: len(findings)})
}
