package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/inventory"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/spf13/cobra"
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
	inventoryTypes      []string
	inventoryOutputFmt  string
	inventoryOutputFile string
)

func init() {
	inventoryCmd.Flags().StringSliceVar(&inventoryTypes, "type", []string{}, "resource types to list (e.g. ec2,s3,lambda); empty = all")
	inventoryCmd.Flags().StringVar(&inventoryOutputFmt, "output", "table", "output format: table, json")
	inventoryCmd.Flags().StringVar(&inventoryOutputFile, "output-file", "", "write output to file")
}

func runInventory(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveInventoryProviders(ctx)
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
		defer func() { _ = f.Close() }()
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

func resolveInventoryProviders(ctx context.Context) ([]cloud.InventoryProvider, error) {
	return providers.Resolve[cloud.InventoryProvider](ctx, providers.WithQuiet(quiet))
}
