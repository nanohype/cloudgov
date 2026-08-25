package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
)

var lambdaCmd = &cobra.Command{
	Use:   "lambda",
	Short: "Serverless function security audits",
}

var lambdaAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit Lambda resource-based policies for public-invoke and confused-deputy patterns",
	Long: `Inspect each Lambda function's resource policy (lambda:GetPolicy) for the
patterns that produce real incidents:

  - Principal: "*"                                         → CRITICAL public invoke
  - Principal: {"AWS": "*"}                                → CRITICAL public invoke
  - Principal: {"AWS": "arn:...other-account..."}          → HIGH cross-account invoke
  - Principal: {"Service": "..."} without SourceAccount /
    SourceArn condition                                    → HIGH confused-deputy risk
  - Action: "*" or "lambda:*"                              → HIGH wildcard

This complements the identity-based IAM scan: ` + "`cloudgov iam scan`" + ` checks who
can do what *from* identities; this checks who can invoke *into* functions.

Currently AWS only.`,
	RunE: runLambdaAudit,
}

var (
	lambdaSeverity   string
	lambdaOutputFmt  string
	lambdaOutputFile string
)

func init() {
	lambdaAuditCmd.Flags().StringVar(&lambdaSeverity, "severity", "LOW", "minimum severity to report")
	lambdaAuditCmd.Flags().StringVar(&lambdaOutputFmt, "output", tableJSONSARIF[0], tableJSONSARIF.usage())
	lambdaAuditCmd.Flags().StringVar(&lambdaOutputFile, "output-file", "", "write output to file")

	lambdaCmd.AddCommand(lambdaAuditCmd)
}

func runLambdaAudit(cmd *cobra.Command, _ []string) error {
	// Refused rather than coerced: an unrecognised level ranks below every
	// real one, so a typo widens a reporting floor instead of failing.
	minSeverity, err := resolveSeverity(lambdaSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	lambdaFormat, err := tableJSONSARIF.resolve(lambdaOutputFmt)
	if err != nil {
		return err
	}
	ctx := cmd.Context()

	providers, err := resolveLambdaPolicyProviders(ctx)
	if err != nil {
		return err
	}

	var allFindings []cloud.LambdaPolicyFinding
	for _, p := range providers {
		found, err := p.AuditLambdaPolicies(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", p.Name(), err)
		}
		allFindings = append(allFindings, found...)
	}

	allFindings = filterLambdaBySeverity(allFindings, minSeverity)

	incomplete := cloud.Incomplete(providers)
	gate(allFindings, func(f cloud.LambdaPolicyFinding) cloud.Severity { return f.Severity })
	gateIncomplete(incomplete)

	w := os.Stdout
	if lambdaOutputFile != "" {
		f, err := os.Create(lambdaOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch lambdaFormat {
	case "json":
		return output.WriteLambdaPolicy(w, allFindings, incomplete)
	case "sarif":
		return output.WriteLambdaSARIF(w, allFindings, Version)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d Lambda policy findings\n\n", len(allFindings))
		}
		output.LambdaPolicyFindings(w, allFindings)
		output.IncompleteNote(w, incomplete)
	}
	return nil
}

func filterLambdaBySeverity(in []cloud.LambdaPolicyFinding, min cloud.Severity) []cloud.LambdaPolicyFinding {
	minRank := cloud.SeverityRank(min)
	out := in[:0]
	for _, f := range in {
		if cloud.SeverityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}

func resolveLambdaPolicyProviders(ctx context.Context) ([]cloud.LambdaPolicyProvider, error) {
	return providers.Resolve[cloud.LambdaPolicyProvider](ctx, providerOptions()...)
}
