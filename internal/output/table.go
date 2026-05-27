package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
	"github.com/stxkxs/matlock/internal/audit"
	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/compliance"
)

var (
	critStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	highStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600"))
	medStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00"))
	lowStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	headerStyle = lipgloss.NewStyle().Bold(true)
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	greenStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00AA00"))
)

func colorSeverity(s cloud.Severity) lipgloss.Style {
	switch s {
	case cloud.SeverityCritical:
		return critStyle
	case cloud.SeverityHigh:
		return highStyle
	case cloud.SeverityMedium:
		return medStyle
	case cloud.SeverityLow:
		return lowStyle
	default:
		return infoStyle
	}
}

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

// BucketFindings renders a storage findings table.
func BucketFindings(w io.Writer, findings []cloud.BucketFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("BUCKET"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Type), f.Provider, f.Bucket, truncate(f.Detail, 70),
		)
	}
	tw.Flush()
}

// OrphanResources renders an orphan resources table with a TOTAL row at the bottom.
func OrphanResources(w io.Writer, orphans []cloud.OrphanResource) {
	if len(orphans) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no orphaned resources found"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("KIND"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("NAME"),
		headerStyle.Render("REGION"),
		headerStyle.Render("$/MONTH"),
		headerStyle.Render("DETAIL"),
	)
	var total float64
	for _, o := range orphans {
		cost := fmt.Sprintf("$%.2f", o.MonthlyCost)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			string(o.Kind), o.Provider, o.Name, o.Region,
			highStyle.Render(cost), truncate(o.Detail, 60),
		)
		total += o.MonthlyCost
	}
	fmt.Fprintf(tw, "%s\t\t\t\t%s\t\n",
		headerStyle.Render("TOTAL"),
		headerStyle.Render(fmt.Sprintf("$%.2f", total)),
	)
	tw.Flush()
}

// CostDiffs renders cost diff tables for each provider.
func CostDiffs(w io.Writer, diffs []cloud.CostDiff) {
	for _, d := range diffs {
		fmt.Fprintf(w, "\n%s  %s → %s  vs  %s → %s\n",
			headerStyle.Render("["+d.Provider+"]"),
			d.BeforeStart.Format("2006-01-02"), d.BeforeEnd.Format("2006-01-02"),
			d.AfterStart.Format("2006-01-02"), d.AfterEnd.Format("2006-01-02"),
		)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			headerStyle.Render("SERVICE"),
			headerStyle.Render("BEFORE"),
			headerStyle.Render("AFTER"),
			headerStyle.Render("DELTA"),
			headerStyle.Render("CHANGE%"),
		)
		for _, e := range d.Entries {
			deltaStr := fmt.Sprintf("%+.2f", e.Delta)
			pctStr := fmt.Sprintf("%+.1f%%", e.PctChange)
			var deltaStyled, pctStyled string
			if e.PctChange > 10 {
				deltaStyled = critStyle.Render(deltaStr)
				pctStyled = critStyle.Render(pctStr)
			} else if e.Delta < 0 {
				deltaStyled = greenStyle.Render(deltaStr)
				pctStyled = greenStyle.Render(pctStr)
			} else {
				deltaStyled = deltaStr
				pctStyled = pctStr
			}
			fmt.Fprintf(tw, "%s\t$%.2f\t$%.2f\t%s\t%s\n",
				e.Service, e.Before, e.After, deltaStyled, pctStyled,
			)
		}
		tw.Flush()
		fmt.Fprintf(w, "\nTotal: $%.2f → $%.2f  (%+.2f)\n", d.TotalBefore, d.TotalAfter, d.TotalDelta)
	}
}

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

// TagFindings renders a missing tags findings table.
func TagFindings(w io.Writer, findings []cloud.TagFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("REGION"),
		headerStyle.Render("MISSING"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		missing := ""
		for i, t := range f.MissingTags {
			if i > 0 {
				missing += ", "
			}
			missing += t
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			sev, f.Provider, f.ResourceType, f.ResourceID, f.Region, missing,
		)
	}
	tw.Flush()
}

// DriftResults renders a drift detection results table.
func DriftResults(w io.Writer, results []cloud.DriftResult) {
	if len(results) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no resources checked"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("STATUS"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("ID"),
		headerStyle.Render("DETAIL"),
	)
	for _, r := range results {
		var statusStyled string
		switch r.Status {
		case cloud.DriftInSync:
			statusStyled = greenStyle.Render("IN_SYNC")
		case cloud.DriftModified:
			statusStyled = critStyle.Render("MODIFIED")
		case cloud.DriftDeleted:
			statusStyled = critStyle.Render("DELETED")
		case cloud.DriftError:
			statusStyled = medStyle.Render("ERROR")
		}

		detail := r.Detail
		if len(r.Fields) > 0 && detail == "" {
			var parts []string
			for _, f := range r.Fields {
				parts = append(parts, fmt.Sprintf("%s: %s→%s", f.Field, f.Expected, f.Actual))
			}
			detail = strings.Join(parts, "; ")
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			statusStyled, r.ResourceName, r.ResourceType, truncate(r.ResourceID, 30), truncate(detail, 60),
		)
	}
	tw.Flush()
}

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

// InventoryResources renders an inventory table with resource details.
func InventoryResources(w io.Writer, resources []cloud.InventoryResource) {
	if len(resources) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no resources found"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("TYPE"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("NAME"),
		headerStyle.Render("REGION"),
		headerStyle.Render("STATUS"),
		headerStyle.Render("TAGS"),
	)
	for _, r := range resources {
		tagStr := formatTags(r.Tags, 50)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Type, r.Provider, truncate(r.Name, 30), r.Region, r.Status, tagStr,
		)
	}
	tw.Flush()

	// Summary by type
	typeCounts := make(map[string]int)
	for _, r := range resources {
		typeCounts[r.Type]++
	}
	types := make([]string, 0, len(typeCounts))
	for t := range typeCounts {
		types = append(types, t)
	}
	sort.Strings(types)
	fmt.Fprintf(w, "\n%s: %d resources", headerStyle.Render("Total"), len(resources))
	for _, t := range types {
		fmt.Fprintf(w, ", %s: %d", t, typeCounts[t])
	}
	fmt.Fprintln(w)
}

func formatTags(tags map[string]string, maxLen int) string {
	if len(tags) == 0 {
		return ""
	}
	parts := make([]string, 0, len(tags))
	for k, v := range tags {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	s := strings.Join(parts, ", ")
	return truncate(s, maxLen)
}

func truncate(s string, n int) string {
	if n < 4 || len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// QuotaUsages renders a quota utilization table.
func QuotaUsages(w io.Writer, quotas []cloud.QuotaUsage) {
	if len(quotas) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no quotas found"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("SERVICE"),
		headerStyle.Render("QUOTA"),
		headerStyle.Render("USED"),
		headerStyle.Render("LIMIT"),
		headerStyle.Render("UTILIZATION"),
	)
	for _, q := range quotas {
		pct := fmt.Sprintf("%.1f%%", q.Utilization)
		var pctStyled string
		switch {
		case q.Utilization >= 80:
			pctStyled = critStyle.Render(pct)
		case q.Utilization >= 50:
			pctStyled = medStyle.Render(pct)
		default:
			pctStyled = greenStyle.Render(pct)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.0f\t%.0f\t%s\n",
			q.Provider, q.Service, q.QuotaName,
			q.Used, q.Limit, pctStyled,
		)
	}
	tw.Flush()
}

// CompareTable renders a diff comparison table.
func CompareTable(w io.Writer, result CompareResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("STATUS"),
		headerStyle.Render("DOMAIN"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("DETAIL"),
	)

	for _, f := range result.New {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			critStyle.Render("+NEW"),
			f.Domain, f.Type, truncate(f.ResourceID, 40), truncate(f.Detail, 60),
		)
	}
	for _, f := range result.Resolved {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			greenStyle.Render("-RESOLVED"),
			f.Domain, f.Type, truncate(f.ResourceID, 40), truncate(f.Detail, 60),
		)
	}
	for _, f := range result.Unchanged {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			dimStyle.Render("=UNCHANGED"),
			f.Domain, f.Type, truncate(f.ResourceID, 40), truncate(f.Detail, 60),
		)
	}
	tw.Flush()

	fmt.Fprintf(w, "\n%s new, %s resolved, %s unchanged\n",
		critStyle.Render(fmt.Sprintf("%d", len(result.New))),
		greenStyle.Render(fmt.Sprintf("%d", len(result.Resolved))),
		dimStyle.Render(fmt.Sprintf("%d", len(result.Unchanged))),
	)
}

// CompareResult mirrors compare.DiffResult to avoid import cycle.
type CompareResult struct {
	New       []CompareFindingType
	Resolved  []CompareFindingType
	Unchanged []CompareFindingType
}

// CompareFindingType mirrors compare.NormalizedFinding to avoid import cycle.
type CompareFindingType struct {
	Domain     string
	Provider   string
	Type       string
	ResourceID string
	Detail     string
	Severity   string
}

// NewCompareResult creates a CompareResult from raw data.
func NewCompareResult(newF, resolved, unchanged []CompareFindingType) CompareResult {
	return CompareResult{New: newF, Resolved: resolved, Unchanged: unchanged}
}

// NewCompareFinding creates a CompareFindingType.
func NewCompareFinding(domain, provider, typ, resourceID, detail, severity string) CompareFindingType {
	return CompareFindingType{
		Domain: domain, Provider: provider, Type: typ,
		ResourceID: resourceID, Detail: detail, Severity: severity,
	}
}
