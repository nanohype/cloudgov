package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

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

type costReport struct {
	Diffs []cloud.CostDiff `json:"diffs"`
}

// WriteCost marshals cost diffs as JSON to w.
func WriteCost(w io.Writer, diffs []cloud.CostDiff) error {
	return writeJSON(w, costReport{Diffs: diffs})
}
