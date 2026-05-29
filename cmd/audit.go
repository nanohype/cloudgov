package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/output/sinks"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run all security and cost scans in one shot",
	Long: `Run a unified full-spectrum audit across IAM, storage, network, orphans,
certs, tags, and secrets. Produces a single combined report.

Skip specific domains with --skip, e.g. --skip iam,certs`,
	RunE: runAudit,
}

var (
	auditSkip         []string
	auditSeverity     string
	auditOutputFmt    string
	auditOutputFile   string
	auditIAMDays      int
	auditCertDays     int
	auditRequiredTags []string
	auditConcurrency  int
	auditSinks        []string
	auditReportURL    string
)

func init() {
	auditCmd.Flags().StringSliceVar(&auditSkip, "skip", []string{}, "domains to skip (iam,storage,network,orphans,certs,tags,secrets)")
	auditCmd.Flags().StringVar(&auditSeverity, "severity", "LOW", "minimum severity to report")
	auditCmd.Flags().StringVar(&auditOutputFmt, "output", "table", "output format: table, json, sarif")
	auditCmd.Flags().StringVar(&auditOutputFile, "output-file", "", "write output to file")
	auditCmd.Flags().IntVar(&auditIAMDays, "iam-days", 90, "IAM audit log lookback period in days")
	auditCmd.Flags().IntVar(&auditCertDays, "cert-days", 90, "certificate expiry warning threshold in days")
	auditCmd.Flags().StringSliceVar(&auditRequiredTags, "require-tags", []string{}, "required tags for tag audit (comma-separated)")
	auditCmd.Flags().IntVar(&auditConcurrency, "concurrency", 10, "max parallel goroutines for IAM scanning")
	auditCmd.Flags().StringSliceVar(&auditSinks, "sink", []string{},
		"notification sink (repeatable): slack:<webhook-url>, webhook:<url>, or pagerduty:<routing-key>")
	auditCmd.Flags().StringVar(&auditReportURL, "report-url", "",
		"optional URL embedded in sink notifications (e.g. link to full report in S3/GCS)")
}

func runAudit(_ *cobra.Command, _ []string) error {
	ctx := context.Background()

	skip := make(map[string]bool)
	for _, s := range auditSkip {
		skip[strings.ToLower(s)] = true
	}

	providers, err := buildAuditProviders(ctx)
	if err != nil {
		return err
	}

	report, err := audit.Run(ctx, providers, audit.Options{
		Skip:         skip,
		MinSeverity:  cloud.Severity(strings.ToUpper(auditSeverity)),
		IAMDays:      auditIAMDays,
		CertDays:     auditCertDays,
		RequiredTags: auditRequiredTags,
		Concurrency:  auditConcurrency,
		Quiet:        quiet,
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if auditOutputFile != "" {
		f, err := os.Create(auditOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch strings.ToLower(auditOutputFmt) {
	case "json":
		if err := output.WriteAudit(w, report); err != nil {
			return err
		}
	case "sarif":
		if err := output.WriteAuditSARIF(w, report, Version); err != nil {
			return err
		}
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nAudit complete in %s\n\n", report.Duration)
		}
		output.AuditReport(w, report)
	}

	if err := notifySinks(ctx, report); err != nil {
		fmt.Fprintf(os.Stderr, "warn: sink delivery: %v\n", err)
	}
	return nil
}

func notifySinks(ctx context.Context, report *audit.Report) error {
	if len(auditSinks) == 0 {
		return nil
	}
	ss, err := sinks.Parse(auditSinks)
	if err != nil {
		return err
	}
	digest := auditDigest(report)
	if !quiet {
		fmt.Fprintf(os.Stderr, "delivering digest to %d sink(s)...\n", len(ss))
	}
	return sinks.SendAll(ctx, ss, digest)
}

func auditDigest(r *audit.Report) sinks.Digest {
	s := r.Summary
	d := sinks.Digest{
		Source:        "cloudgov audit",
		Timestamp:     time.Now(),
		TotalFindings: s.TotalFindings,
		Critical:      s.BySeverity["CRITICAL"],
		High:          s.BySeverity["HIGH"],
		Medium:        s.BySeverity["MEDIUM"],
		Low:           s.BySeverity["LOW"],
		Info:          s.BySeverity["INFO"],
		ReportURL:     auditReportURL,
	}
	for domain, count := range s.ByDomain {
		if count > 0 {
			d.Domains = append(d.Domains, domain)
		}
	}
	d.Provider = digestProvider(r)
	d.Top = topAuditFindings(r, 10)
	return d
}

// digestProvider returns the single cloud if findings are uniformly from
// one provider, "multi" if multiple, "unknown" if none.
func digestProvider(r *audit.Report) string {
	providers := make(map[string]bool)
	for _, f := range r.IAM {
		providers[f.Provider] = true
	}
	for _, f := range r.Storage {
		providers[f.Provider] = true
	}
	for _, f := range r.Network {
		providers[f.Provider] = true
	}
	for _, o := range r.Orphans {
		providers[o.Provider] = true
	}
	for _, f := range r.Certs {
		providers[f.Provider] = true
	}
	for _, f := range r.Tags {
		providers[f.Provider] = true
	}
	for _, f := range r.Secrets {
		providers[f.Provider] = true
	}
	if len(providers) > 1 {
		return "multi"
	}
	for p := range providers {
		return p
	}
	return "unknown"
}

// topAuditFindings returns up to n highest-severity findings across all
// domains so sinks can surface concrete examples, not just counts.
func topAuditFindings(r *audit.Report, n int) []sinks.Finding {
	var all []sinks.Finding
	for _, f := range r.IAM {
		resource := ""
		if f.Principal != nil {
			resource = f.Principal.Name
		}
		all = append(all, sinks.Finding{
			Severity: string(f.Severity), Type: string(f.Type),
			Provider: f.Provider, Resource: resource, Detail: f.Detail,
		})
	}
	for _, f := range r.Storage {
		all = append(all, sinks.Finding{
			Severity: string(f.Severity), Type: string(f.Type),
			Provider: f.Provider, Resource: f.Bucket, Detail: f.Detail,
		})
	}
	for _, f := range r.Network {
		all = append(all, sinks.Finding{
			Severity: string(f.Severity), Type: string(f.Type),
			Provider: f.Provider, Resource: f.Resource, Detail: f.Detail,
		})
	}
	for _, f := range r.Secrets {
		all = append(all, sinks.Finding{
			Severity: string(f.Severity), Type: string(f.Type),
			Provider: f.Provider, Resource: f.Resource, Detail: f.Detail,
		})
	}
	sortFindingsBySeverity(all)
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func sortFindingsBySeverity(fs []sinks.Finding) {
	rank := func(s string) int {
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 4
		case "HIGH":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}
	for i := 1; i < len(fs); i++ {
		j := i
		for j > 0 && rank(fs[j].Severity) > rank(fs[j-1].Severity) {
			fs[j], fs[j-1] = fs[j-1], fs[j]
			j--
		}
	}
}

func buildAuditProviders(ctx context.Context) (audit.Providers, error) {
	type multiProvider interface {
		cloud.Provider
		cloud.IAMProvider
		cloud.StorageProvider
		cloud.NetworkProvider
		cloud.OrphansProvider
		cloud.CertProvider
		cloud.TagProvider
		cloud.SecretsProvider
	}

	p, err := cloudaws.New(ctx)
	if err != nil {
		return audit.Providers{}, fmt.Errorf("initialize aws: %w", err)
	}
	if !p.Detect(ctx) {
		return audit.Providers{}, fmt.Errorf("no AWS credentials detected")
	}
	var mp multiProvider = p

	var providers audit.Providers
	providers.IAM = append(providers.IAM, mp)
	providers.Storage = append(providers.Storage, mp)
	providers.Network = append(providers.Network, mp)
	providers.Orphans = append(providers.Orphans, mp)
	providers.Certs = append(providers.Certs, mp)
	providers.Tags = append(providers.Tags, mp)
	providers.Secrets = append(providers.Secrets, mp)
	return providers, nil
}
