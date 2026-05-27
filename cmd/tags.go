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
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/tags"
)

var tagsCmd = &cobra.Command{
	Use:   "tags",
	Short: "Resource tagging audit",
	RunE:  runTags,
}

var (
	tagsProviders  []string
	tagsRequired   []string
	tagsSeverity   string
	tagsOutputFmt  string
	tagsOutputFile string
)

func init() {
	tagsCmd.Flags().StringSliceVar(&tagsProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	tagsCmd.Flags().StringSliceVar(&tagsRequired, "require", []string{}, "required tag/label keys (comma-separated, e.g. owner,env,cost-center)")
	tagsCmd.Flags().StringVar(&tagsSeverity, "severity", "MEDIUM", "minimum severity to report")
	tagsCmd.Flags().StringVar(&tagsOutputFmt, "output", "table", "output format: table, json")
	tagsCmd.Flags().StringVar(&tagsOutputFile, "output-file", "", "write output to file")
}

func runTags(_ *cobra.Command, _ []string) error {
	if len(tagsRequired) == 0 {
		return fmt.Errorf("--require must specify at least one tag key")
	}

	ctx := context.Background()
	providers, err := resolveTagProviders(ctx, tagsProviders)
	if err != nil {
		return err
	}

	findings, err := tags.Scan(ctx, providers, tags.ScanOptions{
		MinSeverity: cloud.Severity(strings.ToUpper(tagsSeverity)),
		Required:    tagsRequired,
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if tagsOutputFile != "" {
		f, err := os.Create(tagsOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(tagsOutputFmt) {
	case "json":
		return output.WriteTags(w, findings)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d tagging findings\n\n", len(findings))
		}
		output.TagFindings(w, findings)
	}
	return nil
}

func resolveTagProviders(ctx context.Context, names []string) ([]cloud.TagProvider, error) {
	all := buildAllTagProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.TagProvider
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
	byName := make(map[string]cloud.TagProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.TagProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllTagProviders(ctx context.Context) []cloud.TagProvider {
	var providers []cloud.TagProvider
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
