package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

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

type driftReport struct {
	Results []cloud.DriftResult `json:"results"`
	Total   int                 `json:"total"`
}

// WriteDrift marshals drift results as JSON to w.
func WriteDrift(w io.Writer, results []cloud.DriftResult) error {
	return writeJSON(w, driftReport{Results: results, Total: len(results)})
}
