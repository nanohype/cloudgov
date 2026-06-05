package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// K8sFindings renders a Kubernetes RBAC findings table.
func K8sFindings(w io.Writer, findings []cloud.K8sFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("KIND"),
		headerStyle.Render("NAME"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Type), f.Kind, f.Name, truncate(f.Detail, 80),
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

type k8sReport struct {
	Findings []cloud.K8sFinding `json:"findings"`
	Total    int                `json:"total"`
}

// WriteK8sFindings marshals Kubernetes findings as JSON to w.
func WriteK8sFindings(w io.Writer, findings []cloud.K8sFinding) error {
	return writeJSON(w, k8sReport{Findings: findings, Total: len(findings)})
}
