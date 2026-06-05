package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// IAMFindings renders a findings table to w, followed by a severity summary line.
func IAMFindings(w io.Writer, findings []cloud.Finding, totalPrincipals int) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("PRINCIPAL"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		principal := ""
		if f.Principal != nil {
			principal = f.Principal.Name
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			sev, string(f.Type), principal, truncate(f.Detail, 80),
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
	summary := fmt.Sprintf("%s critical, %s high, %s medium across %d principals",
		critStyle.Render(fmt.Sprintf("%d", crit)),
		highStyle.Render(fmt.Sprintf("%d", high)),
		medStyle.Render(fmt.Sprintf("%d", med)),
		totalPrincipals,
	)
	fmt.Fprintf(w, "\n%s\n", summary)
}

type iamReport struct {
	Findings        []cloud.Finding               `json:"findings"`
	Total           int                           `json:"total"`
	Principals      int                           `json:"principals_scanned"`
	UsedPermissions map[string][]cloud.Permission `json:"used_permissions,omitempty"`
}

// WriteIAM marshals IAM findings as JSON to w.
func WriteIAM(w io.Writer, findings []cloud.Finding, principalsScanned int, usedPerms map[string][]cloud.Permission) error {
	return writeJSON(w, iamReport{
		Findings:        findings,
		Total:           len(findings),
		Principals:      principalsScanned,
		UsedPermissions: usedPerms,
	})
}
