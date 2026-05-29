package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/compliance"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/spf13/cobra"
)

var complianceCmd = &cobra.Command{
	Use:   "compliance [benchmark]",
	Short: "Map scan results to compliance benchmark controls",
	Long: `Evaluate cloudgov scan results against compliance benchmarks.

Available benchmarks: cis-aws-v3, soc2

Provide paths to JSON reports from prior cloudgov scans using the report flags.`,
	Args: cobra.ExactArgs(1),
	RunE: runCompliance,
}

var (
	complianceIAMReport     string
	complianceStorageReport string
	complianceNetworkReport string
	complianceCertsReport   string
	complianceTagsReport    string
	complianceOutputFmt     string
	complianceOutputFile    string
)

func init() {
	complianceCmd.Flags().StringVar(&complianceIAMReport, "iam-report", "", "path to IAM scan JSON report")
	complianceCmd.Flags().StringVar(&complianceStorageReport, "storage-report", "", "path to storage audit JSON report")
	complianceCmd.Flags().StringVar(&complianceNetworkReport, "network-report", "", "path to network audit JSON report")
	complianceCmd.Flags().StringVar(&complianceCertsReport, "certs-report", "", "path to certs audit JSON report")
	complianceCmd.Flags().StringVar(&complianceTagsReport, "tags-report", "", "path to tags audit JSON report")
	complianceCmd.Flags().StringVar(&complianceOutputFmt, "output", "table", "output format: table, json")
	complianceCmd.Flags().StringVar(&complianceOutputFile, "output-file", "", "write output to file")
}

func runCompliance(_ *cobra.Command, args []string) error {
	benchmarkID := strings.ToLower(args[0])
	benchmark := compliance.GetBenchmark(benchmarkID)
	if benchmark == nil {
		return fmt.Errorf("unknown benchmark %q; available: %s", benchmarkID, strings.Join(compliance.AvailableBenchmarks(), ", "))
	}

	var input compliance.InputFindings

	if complianceIAMReport != "" {
		findings, err := compliance.LoadIAMReport(complianceIAMReport)
		if err != nil {
			return err
		}
		input.IAM = findings
	}
	if complianceStorageReport != "" {
		findings, err := compliance.LoadStorageReport(complianceStorageReport)
		if err != nil {
			return err
		}
		input.Storage = findings
	}
	if complianceNetworkReport != "" {
		findings, err := compliance.LoadNetworkReport(complianceNetworkReport)
		if err != nil {
			return err
		}
		input.Network = findings
	}
	if complianceCertsReport != "" {
		findings, err := compliance.LoadCertsReport(complianceCertsReport)
		if err != nil {
			return err
		}
		input.Certs = findings
	}
	if complianceTagsReport != "" {
		findings, err := compliance.LoadTagsReport(complianceTagsReport)
		if err != nil {
			return err
		}
		input.Tags = findings
	}

	report := compliance.Evaluate(benchmark, input)

	w := os.Stdout
	if complianceOutputFile != "" {
		f, err := os.Create(complianceOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch strings.ToLower(complianceOutputFmt) {
	case "json":
		return output.WriteCompliance(w, report)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\n%s: %d controls evaluated\n\n", benchmark.Name, report.Summary.Total)
		}
		output.ComplianceReport(w, report)
	}
	return nil
}
