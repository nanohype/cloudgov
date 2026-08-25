package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/output/sinks"
	"github.com/nanohype/cloudgov/internal/providers"
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
	auditCmd.Flags().StringVar(&auditSeverity, "severity", "LOW", severityUsage("minimum severity to report"))
	auditCmd.Flags().StringVar(&auditOutputFmt, "output", tableJSONSARIF[0], tableJSONSARIF.usage())
	auditCmd.Flags().StringVar(&auditOutputFile, "output-file", "", "write output to file")
	auditCmd.Flags().IntVar(&auditIAMDays, "iam-days", 90, "IAM audit log lookback period in days")
	auditCmd.Flags().IntVar(&auditCertDays, "cert-days", 90, "certificate expiry warning threshold in days")
	auditCmd.Flags().StringSliceVar(&auditRequiredTags, "require-tags", []string{}, "required tags for tag audit (comma-separated)")
	auditCmd.Flags().IntVar(&auditConcurrency, "concurrency", 10, "max parallel goroutines for IAM scanning")
	auditCmd.Flags().StringSliceVar(&auditSinks, "sink", []string{},
		"notification sink (repeatable): slack:<webhook-url>, webhook:<url>, or pagerduty:<routing-key>")
	auditCmd.Flags().StringVar(&auditReportURL, "report-url", "",
		"optional URL embedded in sink notifications (e.g. link to full report in S3)")
}

func runAudit(cmd *cobra.Command, _ []string) error {
	// Refused rather than coerced: an unrecognised level ranks below every
	// real one, so a typo widens a reporting floor instead of failing.
	minSeverity, err := resolveSeverity(auditSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	auditFormat, err := tableJSONSARIF.resolve(auditOutputFmt)
	if err != nil {
		return err
	}
	ctx := cmd.Context()

	skip := make(map[string]bool)
	for _, s := range auditSkip {
		skip[strings.ToLower(s)] = true
	}

	providers, err := buildAuditProviders(ctx)
	if err != nil {
		return err
	}

	report, err := audit.Run(ctx, providers, audit.Options{
		Skip:        skip,
		MinSeverity: minSeverity,
		IAMDays:     auditIAMDays,
		CertDays:    auditCertDays,
		TagRules:    cloud.RequiredOnly(auditRequiredTags...),
		Concurrency: auditConcurrency,
		Quiet:       quiet,
	})
	if err != nil {
		return err
	}

	var sevs []cloud.Severity
	for sev, n := range report.Summary.BySeverity {
		if n > 0 {
			sevs = append(sevs, cloud.Severity(sev))
		}
	}
	gate(sevs, func(s cloud.Severity) cloud.Severity { return s })
	// Every per-domain command raises exit 3 on a partial view; the command
	// that runs all seven has to do the same, or the widest scan is the one
	// that reports a permission-limited run as clean.
	gateIncomplete(report.Incomplete)

	w := os.Stdout
	if auditOutputFile != "" {
		f, err := os.Create(auditOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch auditFormat {
	case "json":
		if err := output.WriteAudit(w, report); err != nil {
			return err
		}
	case "sarif":
		if err := output.WriteAuditSARIF(w, report, Version, report.Incomplete); err != nil {
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

// topAuditFindings lifts concrete examples out of a report for a sink digest.
//
// The domain walk lives on audit.Report, beside the struct that defines the
// domains, so a domain added there and not here is a change in one file rather
// than an omission nothing surfaces.
func topAuditFindings(r *audit.Report, n int) []sinks.Finding {
	examples := r.TopFindings(n)
	out := make([]sinks.Finding, 0, len(examples))
	for _, e := range examples {
		out = append(out, sinks.Finding{
			Severity: e.Severity, Type: e.Type,
			Provider: e.Provider, Resource: e.Resource, Detail: e.Detail,
		})
	}
	return out
}

func buildAuditProviders(ctx context.Context) (audit.Providers, error) {
	// Each available registry provider contributes to the capabilities it
	// implements, so the audit tracks the registry with no change here.
	all := providers.Default(providerOptions()...).Available(ctx)
	if len(all) == 0 {
		return audit.Providers{}, errors.New("no cloud provider detected")
	}
	var ap audit.Providers
	for _, p := range all {
		if c, ok := p.(cloud.IAMProvider); ok {
			ap.IAM = append(ap.IAM, c)
		}
		if c, ok := p.(cloud.StorageProvider); ok {
			ap.Storage = append(ap.Storage, c)
		}
		if c, ok := p.(cloud.NetworkProvider); ok {
			ap.Network = append(ap.Network, c)
		}
		if c, ok := p.(cloud.OrphansProvider); ok {
			ap.Orphans = append(ap.Orphans, c)
		}
		if c, ok := p.(cloud.CertProvider); ok {
			ap.Certs = append(ap.Certs, c)
		}
		if c, ok := p.(cloud.TagProvider); ok {
			ap.Tags = append(ap.Tags, c)
		}
		if c, ok := p.(cloud.SecretsProvider); ok {
			ap.Secrets = append(ap.Secrets, c)
		}
	}
	return ap, nil
}
