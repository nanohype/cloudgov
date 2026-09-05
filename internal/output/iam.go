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
	Findings []cloud.Finding `json:"findings"`
	Total    int             `json:"total"`
	// Listed is how many principals the account returned; Scanned is how many
	// were actually analyzed. They are separate fields because they answer
	// different questions and a single number cannot: a principal whose policies
	// could not be read is listed and not scanned, and collapsing the two makes
	// that principal indistinguishable from one that was read and found clean.
	Listed  int `json:"principals_listed"`
	Scanned int `json:"principals_scanned"`
	// Incomplete is what the scan could not read.
	Incomplete []string `json:"incomplete"`
	// Window is the audit-log period the scan covered, and the period every
	// claim in Findings rests on.
	//
	// It is a field rather than only a sentence inside each finding's Detail
	// because a consumer has to be able to read it: a report whose window lives
	// only in prose cannot be checked by anything, and `iam fix` reads this
	// report to decide whether a premise holds. Carried whether or not the
	// window was short, so "what window is this?" has an answer on every report
	// rather than only on the ones that fell short.
	Window          cloud.ScanWindow              `json:"window"`
	UsedPermissions map[string][]cloud.Permission `json:"used_permissions,omitempty"`
}

// WriteIAM marshals IAM findings as JSON to w.
func WriteIAM(w io.Writer, findings []cloud.Finding, principalsListed, principalsScanned int, usedPerms map[string][]cloud.Permission, incomplete []string, window cloud.ScanWindow) error {
	return writeJSON(w, iamReport{
		Findings:        findings,
		Total:           len(findings),
		Window:          window,
		Listed:          principalsListed,
		Scanned:         principalsScanned,
		Incomplete:      observed(incomplete),
		UsedPermissions: usedPerms,
	})
}
