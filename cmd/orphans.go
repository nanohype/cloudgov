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
	orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
	"github.com/nanohype/cloudgov/internal/output"
)

var orphansCmd = &cobra.Command{
	Use:   "orphans",
	Short: "Find unused cloud resources wasting money",
	RunE:  runOrphans,
}

var (
	orphanProviders  []string
	orphanMinCost    float64
	orphanOutputFmt  string
	orphanOutputFile string
)

func init() {
	orphansCmd.Flags().StringSliceVar(&orphanProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	orphansCmd.Flags().Float64Var(&orphanMinCost, "min-cost", 0, "only report orphans with monthly cost above this threshold (USD)")
	orphansCmd.Flags().StringVar(&orphanOutputFmt, "output", "table", "output format: table, json")
	orphansCmd.Flags().StringVar(&orphanOutputFile, "output-file", "", "write output to file")
}

func runOrphans(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveOrphansProviders(ctx, orphanProviders)
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
		defer f.Close()
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

func resolveOrphansProviders(ctx context.Context, names []string) ([]cloud.OrphansProvider, error) {
	all := buildAllOrphansProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.OrphansProvider
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
	byName := make(map[string]cloud.OrphansProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.OrphansProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllOrphansProviders(ctx context.Context) []cloud.OrphansProvider {
	var providers []cloud.OrphansProvider
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
