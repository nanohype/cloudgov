package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/network"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
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
	networkAuditCmd.Flags().StringVar(&networkSeverity, "severity", "LOW", severityUsage("minimum severity to report"))
	networkAuditCmd.Flags().StringVar(&networkOutputFmt, "output", tableJSON[0], tableJSON.usage())
	networkAuditCmd.Flags().StringVar(&networkOutputFile, "output-file", "", "write output to file")
	networkAuditCmd.Flags().BoolVar(&networkFix, "fix", false, "generate shell remediation scripts for each finding")
	networkAuditCmd.Flags().StringVar(&networkOutDir, "out", ".", "directory to write fix scripts (used with --fix)")

	networkCmd.AddCommand(networkAuditCmd)
}

func runNetworkAudit(cmd *cobra.Command, _ []string) error {
	// Refused rather than coerced: an unrecognised level ranks below every
	// real one, so a typo widens a reporting floor instead of failing.
	minSeverity, err := resolveSeverity(networkSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	networkFormat, err := tableJSON.resolve(networkOutputFmt)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	providers, err := resolveNetworkProviders(ctx)
	if err != nil {
		return err
	}

	findings, err := network.Scan(ctx, providers, network.ScanOptions{
		MinSeverity: minSeverity,
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
		defer func() { _ = f.Close() }()
		w = f
	}

	incomplete := cloud.Incomplete(providers)
	gate(findings, func(f cloud.NetworkFinding) cloud.Severity { return f.Severity })
	gateIncomplete(incomplete)

	switch networkFormat {
	case "json":
		if err := output.WriteNetwork(w, findings, incomplete); err != nil {
			return err
		}
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d network findings\n\n", len(findings))
		}
		output.NetworkFindings(w, findings)
		output.IncompleteNote(w, incomplete)
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
	return providers.Resolve[cloud.NetworkProvider](ctx, providerOptions()...)
}
