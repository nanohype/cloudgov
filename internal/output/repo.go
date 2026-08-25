package output

import (
	"fmt"
	"io"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// RepoFindings renders repository-settings findings as a table.
//
// The remediation is printed in full rather than truncated because these are
// GitHub settings a human changes by hand, and the useful part is usually the
// caveat — that enforce_admins removes the escape hatch, or that an
// unprotectable repository needs a plan decision rather than a setting.
func RepoFindings(w io.Writer, findings []cloud.RepoFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "✓ every repository matches the expected settings")
		return
	}
	fmt.Fprintf(w, "%d repository-settings finding(s):\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(w, "  [%s] %-26s %s\n        %s\n        → %s\n\n",
			f.Severity, f.Repo, f.Type, f.Detail, f.Remediation)
	}
}

// repoReport is the JSON envelope for a repository-settings sweep.
//
// It is an envelope rather than a bare array for the same reason every other
// domain's is: the findings alone cannot say whether the sweep read the whole
// organization. A repository `gh` could not reach produces no finding, and
// without `incomplete` that is indistinguishable from a repository that
// conforms.
type repoReport struct {
	Findings []cloud.RepoFinding `json:"findings"`
	Total    int                 `json:"total"`

	// Incomplete lists repositories the sweep was asked to examine and could
	// not. Always present; empty means every repository was read.
	Incomplete []string `json:"incomplete"`
}

// WriteRepo writes a repository-settings report as JSON. An empty findings list
// is an empty array, never null: a consumer distinguishing "clean" from "did not
// run" needs the shape to be stable.
func WriteRepo(w io.Writer, findings []cloud.RepoFinding, incomplete []string) error {
	if findings == nil {
		findings = []cloud.RepoFinding{}
	}
	return writeJSON(w, repoReport{
		Findings:   findings,
		Total:      len(findings),
		Incomplete: observed(incomplete),
	})
}
