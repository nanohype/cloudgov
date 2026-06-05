package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// CertFindings renders a certificate expiry findings table.
func CertFindings(w io.Writer, findings []cloud.CertFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("STATUS"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("DOMAIN"),
		headerStyle.Render("REGION"),
		headerStyle.Render("EXPIRES"),
		headerStyle.Render("DAYS"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		expires := f.ExpiresAt.Format("2006-01-02")
		days := fmt.Sprintf("%d", f.DaysLeft)
		if f.DaysLeft < 0 {
			days = critStyle.Render(days)
			expires = critStyle.Render(expires)
		} else if f.DaysLeft < 7 {
			days = critStyle.Render(days)
		} else if f.DaysLeft < 30 {
			days = highStyle.Render(days)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Status), f.Provider, f.Domain, f.Region, expires, days,
		)
	}
	tw.Flush()
}

type certsReport struct {
	Findings []cloud.CertFinding `json:"findings"`
	Total    int                 `json:"total"`
}

// WriteCerts marshals certificate findings as JSON to w.
func WriteCerts(w io.Writer, findings []cloud.CertFinding) error {
	return writeJSON(w, certsReport{Findings: findings, Total: len(findings)})
}
