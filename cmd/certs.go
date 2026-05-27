package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/nanohype/cloudgov/internal/certs"
	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	cloudazure "github.com/nanohype/cloudgov/internal/cloud/azure"
	cloudgcp "github.com/nanohype/cloudgov/internal/cloud/gcp"
	"github.com/nanohype/cloudgov/internal/output"
)

var certsCmd = &cobra.Command{
	Use:   "certs",
	Short: "TLS certificate expiry audit",
	RunE:  runCerts,
}

var (
	certsProviders  []string
	certsDays       int
	certsSeverity   string
	certsOutputFmt  string
	certsOutputFile string
)

func init() {
	certsCmd.Flags().StringSliceVar(&certsProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	certsCmd.Flags().IntVar(&certsDays, "days", 90, "warn threshold in days (include certs expiring within this many days)")
	certsCmd.Flags().StringVar(&certsSeverity, "severity", "LOW", "minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)")
	certsCmd.Flags().StringVar(&certsOutputFmt, "output", "table", "output format: table, json")
	certsCmd.Flags().StringVar(&certsOutputFile, "output-file", "", "write output to file")
}

func runCerts(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveCertProviders(ctx, certsProviders)
	if err != nil {
		return err
	}

	findings, err := certs.Scan(ctx, providers, certs.ScanOptions{
		MinSeverity: cloud.Severity(strings.ToUpper(certsSeverity)),
		Days:        certsDays,
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if certsOutputFile != "" {
		f, err := os.Create(certsOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(certsOutputFmt) {
	case "json":
		return output.WriteCerts(w, findings)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d certificate findings\n\n", len(findings))
		}
		output.CertFindings(w, findings)
	}
	return nil
}

func resolveCertProviders(ctx context.Context, names []string) ([]cloud.CertProvider, error) {
	all := buildAllCertProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.CertProvider
		for _, p := range all {
			if p.Detect(ctx) {
				detected = append(detected, p)
			}
		}
		if len(detected) == 0 {
			return nil, fmt.Errorf("no cloud provider credentials detected")
		}
		return detected, nil
	}
	byName := make(map[string]cloud.CertProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.CertProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllCertProviders(ctx context.Context) []cloud.CertProvider {
	var providers []cloud.CertProvider
	if p, err := cloudaws.New(ctx); err == nil {
		providers = append(providers, p)
	}
	if p, err := cloudgcp.New(ctx, ""); err == nil {
		providers = append(providers, p)
	}
	if p, err := cloudazure.New(ctx, ""); err == nil {
		providers = append(providers, p)
	}
	return providers
}
