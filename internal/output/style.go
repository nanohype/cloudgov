package output

import (
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/nanohype/cloudgov/internal/cloud"
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
