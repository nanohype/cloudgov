package report

import (
	"embed"
	"fmt"
	"html/template"
	"strings"
)

//go:embed templates/report.html
var templateFS embed.FS

func parseTemplate() (*template.Template, error) {
	funcs := template.FuncMap{
		"lower":       lower,
		"formatCost":  formatCost,
		"pctClass":    pctClass,
		"formatPct":   formatPct,
		"joinStrings": joinStrings,
	}

	tmpl, err := template.New("report.html").Funcs(funcs).ParseFS(templateFS, "templates/report.html")
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	return tmpl, nil
}

func lower(v any) string {
	return strings.ToLower(fmt.Sprintf("%v", v))
}

func formatCost(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.2f", v)
}

func pctClass(v float64) string {
	if v > 10 {
		return "red"
	}
	if v < -10 {
		return "green"
	}
	return ""
}

func formatPct(v float64) string {
	if v > 0 {
		return fmt.Sprintf("+%.1f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}

func joinStrings(s []string, sep string) string {
	return strings.Join(s, sep)
}
