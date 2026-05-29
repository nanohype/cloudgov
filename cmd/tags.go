package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/tags"
	"github.com/spf13/cobra"
)

var tagsCmd = &cobra.Command{
	Use:   "tags",
	Short: "Resource tagging audit",
	RunE:  runTags,
}

var (
	tagsRequired   []string
	tagsSeverity   string
	tagsOutputFmt  string
	tagsOutputFile string
)

func init() {
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
	providers, err := resolveTagProviders(ctx)
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
		defer func() { _ = f.Close() }()
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

func resolveTagProviders(ctx context.Context) ([]cloud.TagProvider, error) {
	p, err := cloudaws.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize aws: %w", err)
	}
	if !p.Detect(ctx) {
		return nil, fmt.Errorf("no AWS credentials detected")
	}
	return []cloud.TagProvider{p}, nil
}
