package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	cloudazure "github.com/nanohype/cloudgov/internal/cloud/azure"
	cloudgcp "github.com/nanohype/cloudgov/internal/cloud/gcp"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/cost"
	"github.com/nanohype/cloudgov/internal/output"
)

var costCmd = &cobra.Command{
	Use:   "cost",
	Short: "Cloud cost analysis",
}

var costDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare spend between two time windows",
	RunE:  runCostDiff,
}

var (
	costProviders  []string
	costDays       int
	costOutputFmt  string
	costOutputFile string
	costThreshold  float64
)

func init() {
	costDiffCmd.Flags().StringSliceVar(&costProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	costDiffCmd.Flags().IntVar(&costDays, "days", 30, "compare last N days vs the N days before that")
	costDiffCmd.Flags().StringVar(&costOutputFmt, "output", "table", "output format: table, json")
	costDiffCmd.Flags().StringVar(&costOutputFile, "output-file", "", "write output to file")
	costDiffCmd.Flags().Float64Var(&costThreshold, "threshold", 0, "only show services with >N% change (e.g. --threshold 20)")

	costCmd.AddCommand(costDiffCmd)
}

func runCostDiff(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveCostProviders(ctx, costProviders)
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
		defer f.Close()
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

func resolveCostProviders(ctx context.Context, names []string) ([]cloud.CostProvider, error) {
	all := buildAllCostProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.CostProvider
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
	byName := make(map[string]cloud.CostProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.CostProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllCostProviders(ctx context.Context) []cloud.CostProvider {
	var providers []cloud.CostProvider
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
