package output

import (
	"fmt"
	"io"

	"github.com/nanohype/cloudgov/internal/audit"
)

// AuditReport renders a unified audit report with sections per domain.
func AuditReport(w io.Writer, report *audit.Report) {
	fmt.Fprintf(w, "%s  completed in %s\n", headerStyle.Render("[audit]"), dimStyle.Render(report.Duration))

	if len(report.IAM) > 0 {
		fmt.Fprintf(w, "\n%s (%d findings)\n", headerStyle.Render("─── IAM"), len(report.IAM))
		IAMFindings(w, report.IAM, 0)
	}
	if len(report.Storage) > 0 {
		fmt.Fprintf(w, "\n%s (%d findings)\n", headerStyle.Render("─── STORAGE"), len(report.Storage))
		BucketFindings(w, report.Storage)
	}
	if len(report.Network) > 0 {
		fmt.Fprintf(w, "\n%s (%d findings)\n", headerStyle.Render("─── NETWORK"), len(report.Network))
		NetworkFindings(w, report.Network)
	}
	if len(report.Orphans) > 0 {
		fmt.Fprintf(w, "\n%s (%d resources)\n", headerStyle.Render("─── ORPHANS"), len(report.Orphans))
		OrphanResources(w, report.Orphans)
	}
	if len(report.Certs) > 0 {
		fmt.Fprintf(w, "\n%s (%d findings)\n", headerStyle.Render("─── CERTS"), len(report.Certs))
		CertFindings(w, report.Certs)
	}
	if len(report.Tags) > 0 {
		fmt.Fprintf(w, "\n%s (%d findings)\n", headerStyle.Render("─── TAGS"), len(report.Tags))
		TagFindings(w, report.Tags)
	}
	if len(report.Secrets) > 0 {
		fmt.Fprintf(w, "\n%s (%d findings)\n", headerStyle.Render("─── SECRETS"), len(report.Secrets))
		SecretFindings(w, report.Secrets)
	}

	// Summary
	s := report.Summary
	fmt.Fprintf(w, "\n%s\n", headerStyle.Render("─── SUMMARY"))
	fmt.Fprintf(w, "  Total findings: %d across %d domains\n", s.TotalFindings, s.DomainsRun)
	if s.BySeverity["CRITICAL"] > 0 {
		fmt.Fprintf(w, "  %s critical\n", critStyle.Render(fmt.Sprintf("%d", s.BySeverity["CRITICAL"])))
	}
	if s.BySeverity["HIGH"] > 0 {
		fmt.Fprintf(w, "  %s high\n", highStyle.Render(fmt.Sprintf("%d", s.BySeverity["HIGH"])))
	}
	if s.BySeverity["MEDIUM"] > 0 {
		fmt.Fprintf(w, "  %s medium\n", medStyle.Render(fmt.Sprintf("%d", s.BySeverity["MEDIUM"])))
	}
	if s.OrphanCost > 0 {
		fmt.Fprintf(w, "  Orphan cost: %s/month\n", highStyle.Render(fmt.Sprintf("$%.2f", s.OrphanCost)))
	}
	if s.DomainsSkipped > 0 {
		fmt.Fprintf(w, "  %s domains skipped\n", dimStyle.Render(fmt.Sprintf("%d", s.DomainsSkipped)))
	}
}

// WriteAudit marshals a full audit report as JSON to w.
func WriteAudit(w io.Writer, report *audit.Report) error {
	return writeJSON(w, report)
}
