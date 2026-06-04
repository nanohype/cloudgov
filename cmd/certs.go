package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/certs"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/spf13/cobra"
)

var certsCmd = &cobra.Command{
	Use:   "certs",
	Short: "TLS certificate expiry audit",
	RunE:  runCerts,
}

var (
	certsDays       int
	certsSeverity   string
	certsOutputFmt  string
	certsOutputFile string
)

func init() {
	certsCmd.Flags().IntVar(&certsDays, "days", 90, "warn threshold in days (include certs expiring within this many days)")
	certsCmd.Flags().StringVar(&certsSeverity, "severity", "LOW", "minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)")
	certsCmd.Flags().StringVar(&certsOutputFmt, "output", "table", "output format: table, json")
	certsCmd.Flags().StringVar(&certsOutputFile, "output-file", "", "write output to file")
}

func runCerts(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveCertProviders(ctx)
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
		defer func() { _ = f.Close() }()
		w = f
	}

	gate(findings, func(f cloud.CertFinding) cloud.Severity { return f.Severity })

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

func resolveCertProviders(ctx context.Context) ([]cloud.CertProvider, error) {
	return providers.Resolve[cloud.CertProvider](ctx, providers.WithQuiet(quiet))
}
