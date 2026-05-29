package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/secrets"
	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Scan cloud resources for leaked credentials",
}

var secretsScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Lambda env, ECS task defs, EC2 user data, Cloud Functions, App Service settings for secrets",
	RunE:  runSecretsScan,
}

var (
	secretsSeverity   string
	secretsOutputFmt  string
	secretsOutputFile string
)

func init() {
	secretsScanCmd.Flags().StringVar(&secretsSeverity, "severity", "LOW", "minimum severity to report")
	secretsScanCmd.Flags().StringVar(&secretsOutputFmt, "output", "table", "output format: table, json, sarif")
	secretsScanCmd.Flags().StringVar(&secretsOutputFile, "output-file", "", "write output to file")

	secretsCmd.AddCommand(secretsScanCmd)
}

func runSecretsScan(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveSecretsProviders(ctx)
	if err != nil {
		return err
	}

	findings, err := secrets.ScanProviders(ctx, providers, secrets.ScanOptions{
		MinSeverity: cloud.Severity(strings.ToUpper(secretsSeverity)),
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if secretsOutputFile != "" {
		f, err := os.Create(secretsOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(secretsOutputFmt) {
	case "json":
		return output.WriteSecrets(w, findings)
	case "sarif":
		return output.WriteSecretsSARIF(w, findings, Version)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d secret findings\n\n", len(findings))
		}
		output.SecretFindings(w, findings)
	}
	return nil
}

func resolveSecretsProviders(ctx context.Context) ([]cloud.SecretsProvider, error) {
	p, err := cloudaws.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize aws: %w", err)
	}
	if !p.Detect(ctx) {
		return nil, fmt.Errorf("no AWS credentials detected")
	}
	return []cloud.SecretsProvider{p}, nil
}
