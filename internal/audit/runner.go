package audit

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nanohype/cloudgov/internal/certs"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/iam"
	"github.com/nanohype/cloudgov/internal/network"
	orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
	"github.com/nanohype/cloudgov/internal/secrets"
	"github.com/nanohype/cloudgov/internal/storage"
	"github.com/nanohype/cloudgov/internal/tags"
)

// Providers holds provider slices for each scan domain.
type Providers struct {
	IAM     []cloud.IAMProvider
	Storage []cloud.StorageProvider
	Network []cloud.NetworkProvider
	Orphans []cloud.OrphansProvider
	Certs   []cloud.CertProvider
	Tags    []cloud.TagProvider
	Secrets []cloud.SecretsProvider
}

// Options controls which scans to run and how.
type Options struct {
	Skip        map[string]bool // domain names to skip (e.g. "iam", "certs")
	MinSeverity cloud.Severity
	IAMDays     int
	CertDays    int
	RequiredTags []string
	Concurrency int
	Quiet       bool
}

// Report contains all findings from a full audit.
type Report struct {
	IAM       []cloud.Finding       `json:"iam,omitempty"`
	Storage   []cloud.BucketFinding  `json:"storage,omitempty"`
	Network   []cloud.NetworkFinding `json:"network,omitempty"`
	Orphans   []cloud.OrphanResource `json:"orphans,omitempty"`
	Certs     []cloud.CertFinding    `json:"certs,omitempty"`
	Tags      []cloud.TagFinding     `json:"tags,omitempty"`
	Secrets   []cloud.SecretFinding  `json:"secrets,omitempty"`
	Summary   ReportSummary          `json:"summary"`
	Duration  string                 `json:"duration"`
}

// ReportSummary holds aggregated finding counts.
type ReportSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByDomain      map[string]int `json:"by_domain"`
	DomainsRun    int            `json:"domains_run"`
	DomainsSkipped int           `json:"domains_skipped"`
	OrphanCost    float64        `json:"orphan_monthly_cost,omitempty"`
}

// Run executes all enabled scan domains in parallel.
func Run(ctx context.Context, providers Providers, opts Options) (*Report, error) {
	start := time.Now()
	report := &Report{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	errs := make([]error, 0)

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	iamDays := opts.IAMDays
	if iamDays <= 0 {
		iamDays = 90
	}

	certDays := opts.CertDays
	if certDays <= 0 {
		certDays = 90
	}

	progress := func(domain, msg string) {
		if !opts.Quiet {
			fmt.Fprintf(os.Stderr, "[audit] %s: %s\n", domain, msg)
		}
	}

	// IAM
	if !opts.Skip["iam"] && len(providers.IAM) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progress("iam", "scanning...")
			var findings []cloud.Finding
			for _, p := range providers.IAM {
				result, err := iam.Scan(ctx, p, iam.ScanOptions{
					Days:        iamDays,
					MinSeverity: opts.MinSeverity,
					Concurrency: concurrency,
				})
				if err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("iam/%s: %w", p.Name(), err))
					mu.Unlock()
					continue
				}
				findings = append(findings, result.Findings...)
			}
			mu.Lock()
			report.IAM = findings
			mu.Unlock()
			progress("iam", fmt.Sprintf("done (%d findings)", len(findings)))
		}()
	}

	// Storage
	if !opts.Skip["storage"] && len(providers.Storage) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progress("storage", "scanning...")
			findings, err := storage.Scan(ctx, providers.Storage, storage.ScanOptions{
				MinSeverity: opts.MinSeverity,
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("storage: %w", err))
				mu.Unlock()
				return
			}
			mu.Lock()
			report.Storage = findings
			mu.Unlock()
			progress("storage", fmt.Sprintf("done (%d findings)", len(findings)))
		}()
	}

	// Network
	if !opts.Skip["network"] && len(providers.Network) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progress("network", "scanning...")
			findings, err := network.Scan(ctx, providers.Network, network.ScanOptions{
				MinSeverity: opts.MinSeverity,
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("network: %w", err))
				mu.Unlock()
				return
			}
			mu.Lock()
			report.Network = findings
			mu.Unlock()
			progress("network", fmt.Sprintf("done (%d findings)", len(findings)))
		}()
	}

	// Orphans
	if !opts.Skip["orphans"] && len(providers.Orphans) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progress("orphans", "scanning...")
			resources, err := orphanscanner.Scan(ctx, providers.Orphans, orphanscanner.ScanOptions{})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("orphans: %w", err))
				mu.Unlock()
				return
			}
			mu.Lock()
			report.Orphans = resources
			mu.Unlock()
			progress("orphans", fmt.Sprintf("done (%d resources)", len(resources)))
		}()
	}

	// Certs
	if !opts.Skip["certs"] && len(providers.Certs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progress("certs", "scanning...")
			findings, err := certs.Scan(ctx, providers.Certs, certs.ScanOptions{
				MinSeverity: opts.MinSeverity,
				Days:        certDays,
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("certs: %w", err))
				mu.Unlock()
				return
			}
			mu.Lock()
			report.Certs = findings
			mu.Unlock()
			progress("certs", fmt.Sprintf("done (%d findings)", len(findings)))
		}()
	}

	// Tags
	if !opts.Skip["tags"] && len(providers.Tags) > 0 && len(opts.RequiredTags) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progress("tags", "scanning...")
			findings, err := tags.Scan(ctx, providers.Tags, tags.ScanOptions{
				MinSeverity: opts.MinSeverity,
				Required:    opts.RequiredTags,
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("tags: %w", err))
				mu.Unlock()
				return
			}
			mu.Lock()
			report.Tags = findings
			mu.Unlock()
			progress("tags", fmt.Sprintf("done (%d findings)", len(findings)))
		}()
	}

	// Secrets
	if !opts.Skip["secrets"] && len(providers.Secrets) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			progress("secrets", "scanning...")
			findings, err := secrets.ScanProviders(ctx, providers.Secrets, secrets.ScanOptions{
				MinSeverity: opts.MinSeverity,
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("secrets: %w", err))
				mu.Unlock()
				return
			}
			mu.Lock()
			report.Secrets = findings
			mu.Unlock()
			progress("secrets", fmt.Sprintf("done (%d findings)", len(findings)))
		}()
	}

	wg.Wait()

	report.Duration = time.Since(start).Truncate(time.Millisecond).String()
	report.Summary = buildSummary(report, opts)

	if len(errs) > 0 && !opts.Quiet {
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "[audit] warn: %v\n", err)
		}
	}

	return report, nil
}

func buildSummary(r *Report, opts Options) ReportSummary {
	s := ReportSummary{
		BySeverity: make(map[string]int),
		ByDomain:   make(map[string]int),
	}

	allDomains := []string{"iam", "storage", "network", "orphans", "certs", "tags", "secrets"}
	for _, d := range allDomains {
		if opts.Skip[d] {
			s.DomainsSkipped++
		} else {
			s.DomainsRun++
		}
	}

	addSeverity := func(sev cloud.Severity) {
		s.BySeverity[string(sev)]++
		s.TotalFindings++
	}

	if len(r.IAM) > 0 {
		s.ByDomain["iam"] = len(r.IAM)
		for _, f := range r.IAM {
			addSeverity(f.Severity)
		}
	}
	if len(r.Storage) > 0 {
		s.ByDomain["storage"] = len(r.Storage)
		for _, f := range r.Storage {
			addSeverity(f.Severity)
		}
	}
	if len(r.Network) > 0 {
		s.ByDomain["network"] = len(r.Network)
		for _, f := range r.Network {
			addSeverity(f.Severity)
		}
	}
	if len(r.Orphans) > 0 {
		s.ByDomain["orphans"] = len(r.Orphans)
		s.TotalFindings += len(r.Orphans)
		s.OrphanCost = orphanscanner.TotalMonthlyCost(r.Orphans)
	}
	if len(r.Certs) > 0 {
		s.ByDomain["certs"] = len(r.Certs)
		for _, f := range r.Certs {
			addSeverity(f.Severity)
		}
	}
	if len(r.Tags) > 0 {
		s.ByDomain["tags"] = len(r.Tags)
		for _, f := range r.Tags {
			addSeverity(f.Severity)
		}
	}
	if len(r.Secrets) > 0 {
		s.ByDomain["secrets"] = len(r.Secrets)
		for _, f := range r.Secrets {
			addSeverity(f.Severity)
		}
	}

	return s
}
