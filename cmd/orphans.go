package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/spf13/cobra"
)

var orphansCmd = &cobra.Command{
	Use:   "orphans",
	Short: "Find unused cloud resources wasting money",
	RunE:  runOrphans,
}

var (
	orphanMinCost    float64
	orphanOutputFmt  string
	orphanOutputFile string
)

func init() {
	orphansCmd.Flags().Float64Var(&orphanMinCost, "min-cost", 0, "only report orphans with monthly cost above this threshold (USD)")
	orphansCmd.Flags().StringVar(&orphanOutputFmt, "output", "table", "output format: table, json")
	orphansCmd.Flags().StringVar(&orphanOutputFile, "output-file", "", "write output to file")
}

func runOrphans(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveOrphansProviders(ctx)
	if err != nil {
		return err
	}

	orphans, err := orphanscanner.Scan(ctx, providers, orphanscanner.ScanOptions{
		MinMonthlyCost: orphanMinCost,
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if orphanOutputFile != "" {
		f, err := os.Create(orphanOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch strings.ToLower(orphanOutputFmt) {
	case "json":
		return output.WriteOrphans(w, orphans)
	default:
		total := orphanscanner.TotalMonthlyCost(orphans)
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d orphaned resources (~$%.2f/month)\n\n", len(orphans), total)
		}
		output.OrphanResources(w, orphans)
	}
	return nil
}

func resolveOrphansProviders(ctx context.Context) ([]cloud.OrphansProvider, error) {
	return providers.Resolve[cloud.OrphansProvider](ctx, providers.WithQuiet(quiet))
}
