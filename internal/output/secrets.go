package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// SecretFindings renders a secret findings table.
func SecretFindings(w io.Writer, findings []cloud.SecretFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("KEY"),
		headerStyle.Render("MATCH"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Type), f.Provider, f.Resource, f.Key, f.Match, truncate(f.Detail, 60),
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
	summary := fmt.Sprintf("\n%s critical, %s high, %s medium",
		critStyle.Render(fmt.Sprintf("%d", crit)),
		highStyle.Render(fmt.Sprintf("%d", high)),
		medStyle.Render(fmt.Sprintf("%d", med)),
	)
	fmt.Fprintln(w, summary)
}

type secretsReport struct {
	Findings []cloud.SecretFinding `json:"findings"`
	Total    int                   `json:"total"`
}

// WriteSecrets marshals secret findings as JSON to w.
func WriteSecrets(w io.Writer, findings []cloud.SecretFinding) error {
	return writeJSON(w, secretsReport{Findings: findings, Total: len(findings)})
}
