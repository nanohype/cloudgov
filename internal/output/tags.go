package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

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

type tagsReport struct {
	Findings []cloud.TagFinding `json:"findings"`
	Total    int                `json:"total"`
}

// WriteTags marshals tag findings as JSON to w.
func WriteTags(w io.Writer, findings []cloud.TagFinding) error {
	return writeJSON(w, tagsReport{Findings: findings, Total: len(findings)})
}
