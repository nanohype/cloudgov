package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	"github.com/nanohype/cloudgov/internal/network"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/spf13/cobra"
)

var networkCmd = &cobra.Command{
	Use:   "network",
	Short: "Network security audit",
}

var networkAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit security groups and firewall rules for overly permissive access",
	RunE:  runNetworkAudit,
}

var (
	networkSeverity   string
	networkOutputFmt  string
	networkOutputFile string
	networkFix        bool
	networkOutDir     string
)

func init() {
	networkAuditCmd.Flags().StringVar(&networkSeverity, "severity", "LOW", "minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)")
	networkAuditCmd.Flags().StringVar(&networkOutputFmt, "output", "table", "output format: table, json")
	networkAuditCmd.Flags().StringVar(&networkOutputFile, "output-file", "", "write output to file")
	networkAuditCmd.Flags().BoolVar(&networkFix, "fix", false, "generate shell remediation scripts for each finding")
	networkAuditCmd.Flags().StringVar(&networkOutDir, "out", ".", "directory to write fix scripts (used with --fix)")

	networkCmd.AddCommand(networkAuditCmd)
}

func runNetworkAudit(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveNetworkProviders(ctx)
	if err != nil {
		return err
	}

	findings, err := network.Scan(ctx, providers, network.ScanOptions{
		MinSeverity: cloud.Severity(strings.ToUpper(networkSeverity)),
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if networkOutputFile != "" {
		f, err := os.Create(networkOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(networkOutputFmt) {
	case "json":
		if err := output.WriteNetwork(w, findings); err != nil {
			return err
		}
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d network findings\n\n", len(findings))
		}
		output.NetworkFindings(w, findings)
	}

	if networkFix {
		files, err := network.WriteFixScripts(findings, networkOutDir)
		if err != nil {
			return fmt.Errorf("write fix scripts: %w", err)
		}
		if !quiet {
			for _, f := range files {
				fmt.Fprintf(os.Stderr, "wrote fix script: %s\n", f)
			}
		}
	}
	return nil
}

func resolveNetworkProviders(ctx context.Context) ([]cloud.NetworkProvider, error) {
	p, err := cloudaws.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize aws: %w", err)
	}
	if !p.Detect(ctx) {
		return nil, fmt.Errorf("no AWS credentials detected")
	}
	return []cloud.NetworkProvider{p}, nil
}
