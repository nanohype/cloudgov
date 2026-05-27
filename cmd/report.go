package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/nanohype/cloudgov/internal/report"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a standalone HTML report from a JSON scan output",
	RunE:  runReport,
}

var (
	reportFrom string
	reportOut  string
	reportType string
	reportOpen bool
)

func init() {
	reportCmd.Flags().StringVar(&reportFrom, "from", "", "path to scan report JSON file (required)")
	reportCmd.Flags().StringVar(&reportOut, "out", "report.html", "output HTML file path")
	reportCmd.Flags().StringVar(&reportType, "type", "auto", "report type: auto, audit, iam, storage, network, orphans, certs, tags, secrets, cost, quotas")
	reportCmd.Flags().BoolVar(&reportOpen, "open", false, "open the report in the default browser after generation")
	reportCmd.MarkFlagRequired("from")
}

func runReport(_ *cobra.Command, _ []string) error {
	err := report.Generate(report.Options{
		InputFile:  reportFrom,
		OutputFile: reportOut,
		ReportType: reportType,
		Open:       reportOpen,
		Version:    Version,
	})
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "report generated: %s\n", reportOut)
	}
	return nil
}
