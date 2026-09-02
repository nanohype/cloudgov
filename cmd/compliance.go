package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
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
	complianceCmd.Flags().StringVar(&complianceOutputFmt, "output", tableJSONSARIF[0], tableJSONSARIF.usage())
	complianceCmd.Flags().StringVar(&complianceOutputFile, "output-file", "", "write output to file")
}

func runCompliance(_ *cobra.Command, args []string) error {
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	complianceFormat, err := tableJSONSARIF.resolve(complianceOutputFmt)
	if err != nil {
		return err
	}
	benchmarkID := strings.ToLower(args[0])
	benchmark := compliance.GetBenchmark(benchmarkID)
	if benchmark == nil {
		return fmt.Errorf("unknown benchmark %q; available: %s", benchmarkID, strings.Join(compliance.AvailableBenchmarks(), ", "))
	}

	var input compliance.InputFindings
	// Every input report's unread record travels with its findings. A benchmark
	// evaluated over a scan that could not read part of the account must not
	// report as a benchmark evaluated over the whole of it.
	var unread []string

	if complianceIAMReport != "" {
		findings, incomplete, err := compliance.LoadIAMReport(complianceIAMReport)
		if err != nil {
			return err
		}
		input.IAM = findings
		for _, entry := range incomplete {
			unread = append(unread, "iam scan report: "+entry)
		}
	}
	if complianceStorageReport != "" {
		findings, incomplete, err := compliance.LoadStorageReport(complianceStorageReport)
		if err != nil {
			return err
		}
		input.Storage = findings
		for _, entry := range incomplete {
			unread = append(unread, "storage audit report: "+entry)
		}
	}
	if complianceNetworkReport != "" {
		findings, incomplete, err := compliance.LoadNetworkReport(complianceNetworkReport)
		if err != nil {
			return err
		}
		input.Network = findings
		for _, entry := range incomplete {
			unread = append(unread, "network audit report: "+entry)
		}
	}
	if complianceCertsReport != "" {
		findings, incomplete, err := compliance.LoadCertsReport(complianceCertsReport)
		if err != nil {
			return err
		}
		input.Certs = findings
		for _, entry := range incomplete {
			unread = append(unread, "certs report: "+entry)
		}
	}
	if complianceTagsReport != "" {
		findings, incomplete, err := compliance.LoadTagsReport(complianceTagsReport)
		if err != nil {
			return err
		}
		input.Tags = findings
		for _, entry := range incomplete {
			unread = append(unread, "tags report: "+entry)
		}
	}

	report := compliance.Evaluate(benchmark, input)
	report.Incomplete = unread

	gate(report.Results, func(r compliance.ControlResult) cloud.Severity {
		if r.Status == compliance.StatusFail {
			return r.Control.Severity
		}
		return cloud.SeverityInfo
	})

	// A control nobody could evaluate is not a control that passed. Without this,
	// a benchmark run with no input reports grades every control NotEvaluated,
	// scores them all Info, and exits 0 under an explicit --fail-on — reporting
	// "benchmark passed" for a benchmark it never checked.
	//
	// Exit 3 rather than 2: an unevaluated control did not fail either, and
	// grading it as a failure would be the same inversion pointed the other way.
	// gateIncomplete leaves an existing exit 2 alone, so a real failure still
	// outranks "could not tell".
	unevaluated := make([]string, 0, len(report.Results))
	for _, r := range report.Results {
		if r.Status == compliance.StatusNotEvaluated {
			unevaluated = append(unevaluated,
				fmt.Sprintf("control %s (%s) not evaluated: %s", r.Control.ID, r.Control.Title, r.Detail))
		}
	}
	// An input the scanner could not fully read is the same fact one layer up: a
	// control evaluated over a partial account is not an evaluated control, and
	// both reach the caller through the same exit code.
	gateIncomplete(append(unevaluated, unread...))

	w := os.Stdout
	if complianceOutputFile != "" {
		f, err := os.Create(complianceOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch complianceFormat {
	case "json":
		return output.WriteCompliance(w, report)
	case "sarif":
		return output.WriteComplianceSARIF(w, report, Version, report.Incomplete)
	default:
		if !quiet {
			// Both numbers, because the benchmark's size and the number of
			// controls this run could decide are different facts and only one of
			// them is a verdict. Summary.Total is every control the benchmark
			// declares, evaluated or not, so printing it alone reported a run
			// that decided nothing as a run that decided everything.
			fmt.Fprintf(os.Stderr, "\n%s: %d of %d controls evaluated\n\n",
				benchmark.Name, report.Summary.Total-report.Summary.NotEvaluated, report.Summary.Total)
		}
		output.ComplianceReport(w, report)
		// The verdicts are what a reader keeps, and --output-file keeps only
		// stdout. Without this the saved table states which controls passed and
		// carries nothing to say the scans behind them were partial.
		output.IncompleteNote(w, report.Incomplete)
	}
	return nil
}
