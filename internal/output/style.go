package output

import (
	"sort"
	"strings"

	"fmt"
	"github.com/charmbracelet/lipgloss"
	"github.com/nanohype/cloudgov/internal/cloud"
	"io"
)

var (
	critStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	highStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600"))
	medStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00"))
	lowStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	headerStyle = lipgloss.NewStyle().Bold(true)
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	// "Could not check" is not a quieter kind of "checked". It reads as a
	// caution, at the same visual weight as the pass and fail counts beside it,
	// so a reader scanning a summary cannot skim past the one number that says
	// the verdict is not evidence.
	unknownStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Bold(true)
	greenStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00AA00"))
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

// IncompleteNote writes what a scan could not read to the same writer the table
// went to.
//
// The exit code and the JSON report already carry this, and gateIncomplete
// writes it to stderr — but a table captured with --output-file, which is how a
// report gets kept, records only stdout. Without this the artifact reads "no
// findings" and carries nothing to say the account was not fully read, so a
// reader coming to the file later cannot tell a clean account from an
// unreadable one. An artifact that cannot be read correctly on its own is a
// false clean with a delivery delay.
func IncompleteNote(w io.Writer, incomplete []string) {
	// A complete run says so. Printing nothing here made "0 findings, and I read
	// everything I was asked to" render identically to "0 findings" from a run
	// that read half the account — and an empty findings table is exactly where a
	// reader stops looking. The JSON envelope solves this by always carrying the
	// key; the table has to say it in words.
	if len(incomplete) == 0 {
		fmt.Fprintf(w, "\n%s every observation this scan was asked to make completed\n",
			greenStyle.Render("COMPLETE"))
		return
	}
	fmt.Fprintf(w, "\n%s %d observation(s) could not be completed; these findings are a partial view\n",
		unknownStyle.Render("INCOMPLETE"), len(incomplete))
	for _, m := range incomplete {
		fmt.Fprintf(w, "  - %s\n", m)
	}
}
