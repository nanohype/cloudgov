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
	"github.com/nanohype/cloudgov/internal/drift"
	"github.com/nanohype/cloudgov/internal/output"
)

var driftCmd = &cobra.Command{
	Use:   "drift <tfstate-path>",
	Short: "Compare live cloud state vs Terraform state files",
	Long: `Detect configuration drift between your Terraform state and live cloud resources.

Reads a terraform.tfstate file and checks each managed resource against the cloud API.
Supports AWS security groups, IAM policies, S3 buckets; GCP firewalls, storage buckets;
Azure NSGs, storage accounts.`,
	Args: cobra.ExactArgs(1),
	RunE: runDrift,
}

var (
	driftProviders    []string
	driftResourceType string
	driftConcurrency  int
	driftOutputFmt    string
	driftOutputFile   string
)

func init() {
	driftCmd.Flags().StringSliceVar(&driftProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect from state if empty")
	driftCmd.Flags().StringVar(&driftResourceType, "resource-type", "", "filter to a single resource type")
	driftCmd.Flags().IntVar(&driftConcurrency, "concurrency", 10, "max concurrent API calls")
	driftCmd.Flags().StringVar(&driftOutputFmt, "output", "table", "output format: table, json")
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

	providers, err := resolveDriftProviders(ctx, resources)
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

	w := os.Stdout
	if driftOutputFile != "" {
		f, err := os.Create(driftOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(driftOutputFmt) {
	case "json":
		return output.WriteDrift(w, results)
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

func resolveDriftProviders(ctx context.Context, resources []drift.ParsedResource) ([]cloud.DriftProvider, error) {
	// Determine which providers are needed from the resources
	needed := make(map[string]bool)
	if len(driftProviders) > 0 {
		for _, name := range driftProviders {
			needed[strings.ToLower(name)] = true
		}
	} else {
		for _, r := range resources {
			needed[r.Provider] = true
		}
	}

	var providers []cloud.DriftProvider
	if needed["aws"] {
		if p, err := cloudaws.New(ctx); err == nil {
			providers = append(providers, p)
		}
	}
	if needed["gcp"] {
		if p, err := cloudgcp.New(ctx, ""); err == nil {
			providers = append(providers, p)
		}
	}
	if needed["azure"] {
		if p, err := cloudazure.New(ctx, ""); err == nil {
			providers = append(providers, p)
		}
	}

	if len(providers) == 0 {
		return nil, fmt.Errorf("no cloud provider credentials detected for the resource types in state file")
	}
	return providers, nil
}
