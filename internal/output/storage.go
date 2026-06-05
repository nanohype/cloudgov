package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

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

type storageReport struct {
	Findings []cloud.BucketFinding `json:"findings"`
	Total    int                   `json:"total"`
}

// WriteStorage marshals storage findings as JSON to w.
func WriteStorage(w io.Writer, findings []cloud.BucketFinding) error {
	return writeJSON(w, storageReport{
		Findings: findings,
		Total:    len(findings),
	})
}
