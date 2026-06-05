package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

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

type quotaReport struct {
	Quotas   []cloud.QuotaUsage `json:"quotas"`
	Total    int                `json:"total"`
	Critical int                `json:"critical"`
	High     int                `json:"high"`
	Medium   int                `json:"medium"`
}

// WriteQuotas marshals quota usage data as JSON to w.
func WriteQuotas(w io.Writer, quotas []cloud.QuotaUsage) error {
	var crit, high, med int
	for _, q := range quotas {
		switch q.EffectiveSeverity() {
		case cloud.SeverityCritical:
			crit++
		case cloud.SeverityHigh:
			high++
		case cloud.SeverityMedium:
			med++
		}
	}
	return writeJSON(w, quotaReport{
		Quotas:   quotas,
		Total:    len(quotas),
		Critical: crit,
		High:     high,
		Medium:   med,
	})
}
