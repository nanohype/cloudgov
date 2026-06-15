package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/nanohype/cloudgov/internal/tags"
	"github.com/spf13/cobra"
)

var tagsCmd = &cobra.Command{
	Use:   "tags",
	Short: "Resource tagging audit",
	RunE:  runTags,
}

var (
	tagsRequired     []string
	tagsStandardFile string
	tagsSeverity     string
	tagsOutputFmt    string
	tagsOutputFile   string
)

func init() {
	tagsCmd.Flags().StringSliceVar(&tagsRequired, "require", []string{}, "required tag/label keys (comma-separated, e.g. owner,env,cost-center)")
	tagsCmd.Flags().StringVar(&tagsStandardFile, "standard-file", "", "path to a nanohype resource-tagging standard JSON; gates on its required AWS keys (content.required_by_surface.aws)")
	tagsCmd.Flags().StringVar(&tagsSeverity, "severity", "MEDIUM", "minimum severity to report")
	tagsCmd.Flags().StringVar(&tagsOutputFmt, "output", "table", "output format: table, json")
	tagsCmd.Flags().StringVar(&tagsOutputFile, "output-file", "", "write output to file")
}

func runTags(_ *cobra.Command, _ []string) error {
	// Precedence: explicit --require wins (ad-hoc override); else the required
	// AWS keys from --standard-file; else error. Keeps --require working for
	// one-off checks while --standard-file is the CI gate's source of truth.
	required := tagsRequired
	if len(required) == 0 && tagsStandardFile != "" {
		loaded, err := tags.LoadRequired(tagsStandardFile)
		if err != nil {
			return err
		}
		required = loaded
	}
	if len(required) == 0 {
		return fmt.Errorf("specify required tag keys via --require or --standard-file")
	}

	ctx := context.Background()
	providers, err := resolveTagProviders(ctx)
	if err != nil {
		return err
	}

	findings, err := tags.Scan(ctx, providers, tags.ScanOptions{
		MinSeverity: cloud.Severity(strings.ToUpper(tagsSeverity)),
		Required:    required,
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

	gate(findings, func(f cloud.TagFinding) cloud.Severity { return f.Severity })

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
	return providers.Resolve[cloud.TagProvider](ctx, providers.WithQuiet(quiet))
}
