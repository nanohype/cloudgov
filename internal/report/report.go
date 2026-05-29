package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compare"
	orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
)

// Options controls report generation.
type Options struct {
	InputFile  string
	OutputFile string
	ReportType string // "auto" or specific type
	Open       bool
	Version    string
}

// TemplateData is the data model passed to the HTML template.
type TemplateData struct {
	Title       string
	ReportType  string
	GeneratedAt string
	Version     string
	Duration    string

	// Audit summary
	Summary *audit.ReportSummary

	// Domain findings
	IAMFindings     []cloud.Finding
	StorageFindings []cloud.BucketFinding
	NetworkFindings []cloud.NetworkFinding
	OrphanResources []cloud.OrphanResource
	CertFindings    []cloud.CertFinding
	TagFindings     []cloud.TagFinding
	SecretFindings  []cloud.SecretFinding
	CostDiffs       []cloud.CostDiff
	QuotaUsages     []cloud.QuotaUsage

	// Summary counts
	TotalFindings int
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int

	ByDomain          map[string]int
	OrphanMonthlyCost float64
}

// DetectType detects the report type from JSON data.
func DetectType(data []byte) string {
	return string(compare.DetectType(data))
}

// Generate reads a JSON report and produces an HTML file.
func Generate(opts Options) error {
	data, err := os.ReadFile(opts.InputFile)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	reportType := opts.ReportType
	if reportType == "" || reportType == "auto" {
		reportType = DetectType(data)
	}

	out, err := os.Create(opts.OutputFile)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	if err := Render(out, data, reportType, opts.Version); err != nil {
		return fmt.Errorf("render report: %w", err)
	}

	if opts.Open {
		openBrowser(opts.OutputFile)
	}

	return nil
}

// Render writes the HTML report to w without creating a file.
func Render(w io.Writer, data []byte, reportType, version string) error {
	td, err := buildTemplateData(data, reportType, version)
	if err != nil {
		return err
	}

	tmpl, err := parseTemplate()
	if err != nil {
		return err
	}

	return tmpl.Execute(w, td)
}

func buildTemplateData(data []byte, reportType, version string) (*TemplateData, error) {
	td := &TemplateData{
		Title:       "CloudGov Security Report",
		ReportType:  reportType,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Version:     version,
		ByDomain:    make(map[string]int),
	}

	switch compare.ReportType(reportType) {
	case compare.ReportTypeAudit:
		return buildAuditReport(data, td)
	case compare.ReportTypeIAM:
		return buildIAMReport(data, td)
	case compare.ReportTypeStorage:
		return buildStorageReport(data, td)
	case compare.ReportTypeNetwork:
		return buildNetworkReport(data, td)
	case compare.ReportTypeOrphans:
		return buildOrphansReport(data, td)
	case compare.ReportTypeCerts:
		return buildCertsReport(data, td)
	case compare.ReportTypeTags:
		return buildTagsReport(data, td)
	case compare.ReportTypeSecrets:
		return buildSecretsReport(data, td)
	case compare.ReportTypeCost:
		return buildCostReport(data, td)
	case compare.ReportTypeQuotas:
		return buildQuotasReport(data, td)
	default:
		return nil, fmt.Errorf("unsupported report type: %s", reportType)
	}
}

func buildAuditReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report audit.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse audit report: %w", err)
	}

	td.Title = "CloudGov Audit Report"
	td.Duration = report.Duration
	td.Summary = &report.Summary
	td.IAMFindings = report.IAM
	td.StorageFindings = report.Storage
	td.NetworkFindings = report.Network
	td.OrphanResources = report.Orphans
	td.CertFindings = report.Certs
	td.TagFindings = report.Tags
	td.SecretFindings = report.Secrets

	td.TotalFindings = report.Summary.TotalFindings
	td.ByDomain = report.Summary.ByDomain
	td.OrphanMonthlyCost = report.Summary.OrphanCost

	if report.Summary.BySeverity != nil {
		td.Critical = report.Summary.BySeverity["CRITICAL"]
		td.High = report.Summary.BySeverity["HIGH"]
		td.Medium = report.Summary.BySeverity["MEDIUM"]
		td.Low = report.Summary.BySeverity["LOW"]
		td.Info = report.Summary.BySeverity["INFO"]
	}

	return td, nil
}

func buildIAMReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Findings []cloud.Finding `json:"findings"`
		Total    int             `json:"total"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse IAM report: %w", err)
	}

	td.Title = "CloudGov IAM Report"
	td.IAMFindings = report.Findings
	td.TotalFindings = report.Total
	td.ByDomain["iam"] = report.Total
	countSeverities(td, iamSeverities(report.Findings))

	return td, nil
}

func buildStorageReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Findings []cloud.BucketFinding `json:"findings"`
		Total    int                   `json:"total"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse storage report: %w", err)
	}

	td.Title = "CloudGov Storage Report"
	td.StorageFindings = report.Findings
	td.TotalFindings = report.Total
	td.ByDomain["storage"] = report.Total
	countSeverities(td, storageSeverities(report.Findings))

	return td, nil
}

func buildNetworkReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Findings []cloud.NetworkFinding `json:"findings"`
		Total    int                    `json:"total"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse network report: %w", err)
	}

	td.Title = "CloudGov Network Report"
	td.NetworkFindings = report.Findings
	td.TotalFindings = report.Total
	td.ByDomain["network"] = report.Total
	countSeverities(td, networkSeverities(report.Findings))

	return td, nil
}

func buildOrphansReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Resources []cloud.OrphanResource `json:"resources"`
		Total     int                    `json:"total"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse orphans report: %w", err)
	}

	td.Title = "CloudGov Orphans Report"
	td.OrphanResources = report.Resources
	td.TotalFindings = report.Total
	td.ByDomain["orphans"] = report.Total
	td.OrphanMonthlyCost = orphanscanner.TotalMonthlyCost(report.Resources)

	return td, nil
}

func buildCertsReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Findings []cloud.CertFinding `json:"findings"`
		Total    int                 `json:"total"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse certs report: %w", err)
	}

	td.Title = "CloudGov Certificates Report"
	td.CertFindings = report.Findings
	td.TotalFindings = report.Total
	td.ByDomain["certs"] = report.Total
	countSeverities(td, certSeverities(report.Findings))

	return td, nil
}

func buildTagsReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Findings []cloud.TagFinding `json:"findings"`
		Total    int                `json:"total"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse tags report: %w", err)
	}

	td.Title = "CloudGov Tags Report"
	td.TagFindings = report.Findings
	td.TotalFindings = report.Total
	td.ByDomain["tags"] = report.Total
	countSeverities(td, tagSeverities(report.Findings))

	return td, nil
}

func buildSecretsReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Findings []cloud.SecretFinding `json:"findings"`
		Total    int                   `json:"total"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse secrets report: %w", err)
	}

	td.Title = "CloudGov Secrets Report"
	td.SecretFindings = report.Findings
	td.TotalFindings = report.Total
	td.ByDomain["secrets"] = report.Total
	countSeverities(td, secretSeverities(report.Findings))

	return td, nil
}

func buildCostReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Diffs []cloud.CostDiff `json:"diffs"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse cost report: %w", err)
	}

	td.Title = "CloudGov Cost Report"
	td.CostDiffs = report.Diffs

	return td, nil
}

func buildQuotasReport(data []byte, td *TemplateData) (*TemplateData, error) {
	var report struct {
		Quotas []cloud.QuotaUsage `json:"quotas"`
		Total  int                `json:"total"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse quotas report: %w", err)
	}

	td.Title = "CloudGov Quota Report"
	td.QuotaUsages = report.Quotas
	td.TotalFindings = report.Total
	td.ByDomain["quotas"] = report.Total

	for _, q := range report.Quotas {
		switch cloud.QuotaSeverity(q.Utilization) {
		case cloud.SeverityCritical:
			td.Critical++
		case cloud.SeverityHigh:
			td.High++
		case cloud.SeverityMedium:
			td.Medium++
		default:
			td.Low++
		}
	}

	return td, nil
}

func countSeverities(td *TemplateData, severities []cloud.Severity) {
	for _, s := range severities {
		switch s {
		case cloud.SeverityCritical:
			td.Critical++
		case cloud.SeverityHigh:
			td.High++
		case cloud.SeverityMedium:
			td.Medium++
		case cloud.SeverityLow:
			td.Low++
		default:
			td.Info++
		}
	}
}

func iamSeverities(findings []cloud.Finding) []cloud.Severity {
	s := make([]cloud.Severity, len(findings))
	for i, f := range findings {
		s[i] = f.Severity
	}
	return s
}

func storageSeverities(findings []cloud.BucketFinding) []cloud.Severity {
	s := make([]cloud.Severity, len(findings))
	for i, f := range findings {
		s[i] = f.Severity
	}
	return s
}

func networkSeverities(findings []cloud.NetworkFinding) []cloud.Severity {
	s := make([]cloud.Severity, len(findings))
	for i, f := range findings {
		s[i] = f.Severity
	}
	return s
}

func certSeverities(findings []cloud.CertFinding) []cloud.Severity {
	s := make([]cloud.Severity, len(findings))
	for i, f := range findings {
		s[i] = f.Severity
	}
	return s
}

func tagSeverities(findings []cloud.TagFinding) []cloud.Severity {
	s := make([]cloud.Severity, len(findings))
	for i, f := range findings {
		s[i] = f.Severity
	}
	return s
}

func secretSeverities(findings []cloud.SecretFinding) []cloud.Severity {
	s := make([]cloud.Severity, len(findings))
	for i, f := range findings {
		s[i] = f.Severity
	}
	return s
}

func openBrowser(path string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{path}
	case "linux":
		cmd = "xdg-open"
		args = []string{path}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", path}
	default:
		return
	}

	exec.Command(cmd, args...).Start()
}
