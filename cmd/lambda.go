package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stxkxs/matlock/internal/cloud"
	cloudaws "github.com/stxkxs/matlock/internal/cloud/aws"
	"github.com/stxkxs/matlock/internal/output"
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

This complements the identity-based IAM scan: ` + "`matlock iam scan`" + ` checks who
can do what *from* identities; this checks who can invoke *into* functions.

Currently AWS only.`,
	RunE: runLambdaAudit,
}

var (
	lambdaProviders  []string
	lambdaSeverity   string
	lambdaOutputFmt  string
	lambdaOutputFile string
)

func init() {
	lambdaAuditCmd.Flags().StringSliceVar(&lambdaProviders, "provider", []string{"aws"}, "cloud providers (currently only aws is supported)")
	lambdaAuditCmd.Flags().StringVar(&lambdaSeverity, "severity", "LOW", "minimum severity to report")
	lambdaAuditCmd.Flags().StringVar(&lambdaOutputFmt, "output", "table", "output format: table, json")
	lambdaAuditCmd.Flags().StringVar(&lambdaOutputFile, "output-file", "", "write output to file")

	lambdaCmd.AddCommand(lambdaAuditCmd)
}

func runLambdaAudit(_ *cobra.Command, _ []string) error {
	ctx := context.Background()

	var allFindings []cloud.LambdaPolicyFinding
	for _, name := range lambdaProviders {
		if strings.ToLower(name) != "aws" {
			return fmt.Errorf("provider %q: lambda audit currently only supports aws", name)
		}
		p, err := cloudaws.New(ctx)
		if err != nil {
			return fmt.Errorf("aws: %w", err)
		}
		findings, err := p.AuditLambdaPolicies(ctx)
		if err != nil {
			return err
		}
		allFindings = append(allFindings, findings...)
	}

	allFindings = filterLambdaBySeverity(allFindings, cloud.Severity(strings.ToUpper(lambdaSeverity)))

	w := os.Stdout
	if lambdaOutputFile != "" {
		f, err := os.Create(lambdaOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(lambdaOutputFmt) {
	case "json":
		return output.WriteLambdaPolicy(w, allFindings)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d Lambda policy findings\n\n", len(allFindings))
		}
		output.LambdaPolicyFindings(w, allFindings)
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
