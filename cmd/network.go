package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stxkxs/matlock/internal/cloud"
	cloudaws "github.com/stxkxs/matlock/internal/cloud/aws"
	cloudazure "github.com/stxkxs/matlock/internal/cloud/azure"
	cloudgcp "github.com/stxkxs/matlock/internal/cloud/gcp"
	"github.com/stxkxs/matlock/internal/network"
	"github.com/stxkxs/matlock/internal/output"
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
	networkProviders  []string
	networkSeverity   string
	networkOutputFmt  string
	networkOutputFile string
	networkFix        bool
	networkOutDir     string
)

func init() {
	networkAuditCmd.Flags().StringSliceVar(&networkProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	networkAuditCmd.Flags().StringVar(&networkSeverity, "severity", "LOW", "minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)")
	networkAuditCmd.Flags().StringVar(&networkOutputFmt, "output", "table", "output format: table, json")
	networkAuditCmd.Flags().StringVar(&networkOutputFile, "output-file", "", "write output to file")
	networkAuditCmd.Flags().BoolVar(&networkFix, "fix", false, "generate shell remediation scripts for each finding")
	networkAuditCmd.Flags().StringVar(&networkOutDir, "out", ".", "directory to write fix scripts (used with --fix)")

	networkCmd.AddCommand(networkAuditCmd)
}

func runNetworkAudit(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveNetworkProviders(ctx, networkProviders)
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

func resolveNetworkProviders(ctx context.Context, names []string) ([]cloud.NetworkProvider, error) {
	all := buildAllNetworkProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.NetworkProvider
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
	byName := make(map[string]cloud.NetworkProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.NetworkProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllNetworkProviders(ctx context.Context) []cloud.NetworkProvider {
	var providers []cloud.NetworkProvider
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
