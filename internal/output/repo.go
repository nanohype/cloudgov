package output

import (
	"encoding/json"
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

// WriteRepo writes findings as JSON. An empty result is an empty array, never
// null: a consumer distinguishing "clean" from "did not run" needs the shape to
// be stable.
func WriteRepo(w io.Writer, findings []cloud.RepoFinding) error {
	if findings == nil {
		findings = []cloud.RepoFinding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}
