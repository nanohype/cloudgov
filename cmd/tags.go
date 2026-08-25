package cmd

import (
	"context"
	"fmt"
	"os"

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
	tagsCmd.Flags().StringVar(&tagsStandardFile, "standard-file", "", "path to a nanohype resource-tagging standard JSON; gates on its whole AWS tag policy — the required keys and the conditional rules")
	tagsCmd.Flags().StringVar(&tagsSeverity, "severity", "MEDIUM", "minimum severity to report")
	tagsCmd.Flags().StringVar(&tagsOutputFmt, "output", tableJSON[0], tableJSON.usage())
	tagsCmd.Flags().StringVar(&tagsOutputFile, "output-file", "", "write output to file")
}

func runTags(cmd *cobra.Command, _ []string) error {
	// Refused rather than coerced: an unrecognised level ranks below every
	// real one, so a typo widens a reporting floor instead of failing.
	minSeverity, err := resolveSeverity(tagsSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	tagsFormat, err := tableJSON.resolve(tagsOutputFmt)
	if err != nil {
		return err
	}
	// Precedence: explicit --require wins (ad-hoc override); else the whole tag
	// policy from --standard-file. Keeps --require working for one-off checks
	// while --standard-file is the CI gate's source of truth.
	//
	// Only --standard-file can carry conditional rules: a rule that applies to
	// some resource kinds and not others is not expressible as a list of keys,
	// and pretending otherwise would apply a backup-policy requirement to every
	// EC2 instance in the account.
	rules := cloud.RequiredOnly(tagsRequired...)
	var unenforceable []string
	if len(tagsRequired) == 0 && tagsStandardFile != "" {
		loaded, gaps, err := tags.LoadRules(tagsStandardFile)
		if err != nil {
			return err
		}
		rules, unenforceable = loaded, gaps
	}
	if rules.Empty() {
		return fmt.Errorf("specify required tag keys via --require or --standard-file")
	}

	ctx := cmd.Context()
	providers, err := resolveTagProviders(ctx)
	if err != nil {
		return err
	}

	findings, err := tags.Scan(ctx, providers, tags.ScanOptions{
		MinSeverity: minSeverity,
		Rules:       rules,
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

	// A rule the standard declares and this tool cannot evaluate is an
	// observation the run was asked to make and could not, so it travels with the
	// provider's own unread list rather than as a note nobody reads.
	incomplete := append(cloud.Incomplete(providers), unenforceable...)
	gate(findings, func(f cloud.TagFinding) cloud.Severity { return f.Severity })
	gateIncomplete(incomplete)

	switch tagsFormat {
	case "json":
		return output.WriteTags(w, findings, incomplete)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d tagging findings\n\n", len(findings))
		}
		output.TagFindings(w, findings)
		output.IncompleteNote(w, incomplete)
	}
	return nil
}

func resolveTagProviders(ctx context.Context) ([]cloud.TagProvider, error) {
	return providers.Resolve[cloud.TagProvider](ctx, providerOptions()...)
}
