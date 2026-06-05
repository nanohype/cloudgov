package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/cost"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/spf13/cobra"
)

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "AWS cost analysis",
}

var costDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare spend between two time windows",
	RunE:  runCostDiff,
}

var (
	costDays       int
	costOutputFmt  string
	costOutputFile string
	costThreshold  float64
)

func init() {
	costDiffCmd.Flags().IntVar(&costDays, "days", 30, "compare last N days vs the N days before that")
	costDiffCmd.Flags().StringVar(&costOutputFmt, "output", "table", "output format: table, json")
	costDiffCmd.Flags().StringVar(&costOutputFile, "output-file", "", "write output to file")
	costDiffCmd.Flags().Float64Var(&costThreshold, "threshold", 0, "only show services with >N% change (e.g. --threshold 20)")

	costCmd.AddCommand(costDiffCmd)
}

func runCostDiff(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveCostProviders(ctx)
	if err != nil {
		return err
	}

	diffs, err := cost.Scan(ctx, providers, cost.ScanOptions{Days: costDays, Threshold: costThreshold})
	if err != nil {
		return err
	}

	w := os.Stdout
	if costOutputFile != "" {
		f, err := os.Create(costOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch strings.ToLower(costOutputFmt) {
	case "json":
		return output.WriteCost(w, diffs)
	default:
		output.CostDiffs(w, diffs)
	}
	return nil
}

func resolveCostProviders(ctx context.Context) ([]cloud.CostProvider, error) {
	return providers.Resolve[cloud.CostProvider](ctx, providers.WithQuiet(quiet))
}
