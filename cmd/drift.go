package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/drift"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/spf13/cobra"
)

var driftCmd = &cobra.Command{
	Use:   "drift <tfstate-path>",
	Short: "Compare live cloud state vs Terraform state files",
	Long: `Detect configuration drift between your Terraform state and live cloud resources.

Reads a terraform.tfstate file and checks each managed resource against the AWS API.
Supports AWS security groups, IAM policies, and S3 buckets.`,
	Args: cobra.ExactArgs(1),
	RunE: runDrift,
}

var (
	driftResourceType string
	driftConcurrency  int
	driftOutputFmt    string
	driftOutputFile   string
)

func init() {
	driftCmd.Flags().StringVar(&driftResourceType, "resource-type", "", "filter to a single resource type")
	driftCmd.Flags().IntVar(&driftConcurrency, "concurrency", 10, "max concurrent API calls")
	driftCmd.Flags().StringVar(&driftOutputFmt, "output", "table", "output format: table, json, sarif")
	driftCmd.Flags().StringVar(&driftOutputFile, "output-file", "", "write output to file")
}

func runDrift(_ *cobra.Command, args []string) error {
	ctx := context.Background()

	resources, err := drift.ParseTFState(args[0])
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "parsed %d managed resources from %s\n", len(resources), args[0])
	}

	providers, err := resolveDriftProviders(ctx)
	if err != nil {
		return err
	}

	results, err := drift.Scan(ctx, resources, providers, drift.ScanOptions{
		Concurrency:  driftConcurrency,
		ResourceType: driftResourceType,
	})
	if err != nil {
		return err
	}

	drifted := false
	for _, r := range results {
		if r.Status == cloud.DriftModified || r.Status == cloud.DriftDeleted {
			drifted = true
			break
		}
	}
	gateBool(drifted)

	w := os.Stdout
	if driftOutputFile != "" {
		f, err := os.Create(driftOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch strings.ToLower(driftOutputFmt) {
	case "json":
		return output.WriteDrift(w, results)
	case "sarif":
		return output.WriteDriftSARIF(w, results, Version)
	default:
		if !quiet {
			var modified, deleted, inSync, errored int
			for _, r := range results {
				switch r.Status {
				case cloud.DriftModified:
					modified++
				case cloud.DriftDeleted:
					deleted++
				case cloud.DriftInSync:
					inSync++
				case cloud.DriftError:
					errored++
				}
			}
			fmt.Fprintf(os.Stderr, "\n%d resources checked: %d in sync, %d modified, %d deleted, %d errors\n\n",
				len(results), inSync, modified, deleted, errored)
		}
		output.DriftResults(w, results)
	}
	return nil
}

func resolveDriftProviders(ctx context.Context) ([]cloud.DriftProvider, error) {
	return providers.Resolve[cloud.DriftProvider](ctx, providers.WithQuiet(quiet))
}
