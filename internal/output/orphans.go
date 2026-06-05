package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

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

type orphansReport struct {
	Resources           []cloud.OrphanResource `json:"resources"`
	Total               int                    `json:"total"`
	EstimatedMonthlyUSD float64                `json:"estimated_monthly_usd"`
}

// WriteOrphans marshals orphan resources as JSON to w.
func WriteOrphans(w io.Writer, orphans []cloud.OrphanResource) error {
	var total float64
	for _, o := range orphans {
		total += o.MonthlyCost
	}
	return writeJSON(w, orphansReport{
		Resources:           orphans,
		Total:               len(orphans),
		EstimatedMonthlyUSD: total,
	})
}
