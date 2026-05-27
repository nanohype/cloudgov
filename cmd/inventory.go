package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	cloudazure "github.com/nanohype/cloudgov/internal/cloud/azure"
	cloudgcp "github.com/nanohype/cloudgov/internal/cloud/gcp"
	"github.com/nanohype/cloudgov/internal/inventory"
	"github.com/nanohype/cloudgov/internal/output"
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "List all cloud resources across providers",
	Long: `List all cloud resources with type, region, tags, and creation date.
Groups by type and region for a complete asset overview.

Filter by resource type with --type, e.g. --type ec2,s3,lambda`,
	RunE: runInventory,
}

var (
	inventoryProviders  []string
	inventoryTypes      []string
	inventoryOutputFmt  string
	inventoryOutputFile string
)

func init() {
	inventoryCmd.Flags().StringSliceVar(&inventoryProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	inventoryCmd.Flags().StringSliceVar(&inventoryTypes, "type", []string{}, "resource types to list (e.g. ec2,s3,lambda); empty = all")
	inventoryCmd.Flags().StringVar(&inventoryOutputFmt, "output", "table", "output format: table, json")
	inventoryCmd.Flags().StringVar(&inventoryOutputFile, "output-file", "", "write output to file")
}

func runInventory(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveInventoryProviders(ctx, inventoryProviders)
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Listing resources...\n")
	}

	resources, err := inventory.Scan(ctx, providers, inventory.ScanOptions{
		TypeFilter: inventoryTypes,
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if inventoryOutputFile != "" {
		f, err := os.Create(inventoryOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(inventoryOutputFmt) {
	case "json":
		return output.WriteInventory(w, resources)
	default:
		if !quiet {
			summary := inventory.Summarize(resources)
			fmt.Fprintf(os.Stderr, "\nFound %d resources\n\n", summary.Total)
		}
		output.InventoryResources(w, resources)
	}
	return nil
}

func resolveInventoryProviders(ctx context.Context, names []string) ([]cloud.InventoryProvider, error) {
	all := buildAllInventoryProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.InventoryProvider
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
	byName := make(map[string]cloud.InventoryProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.InventoryProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllInventoryProviders(ctx context.Context) []cloud.InventoryProvider {
	var providers []cloud.InventoryProvider
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
