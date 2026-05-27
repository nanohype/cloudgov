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
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/secrets"
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
	secretsProviders  []string
	secretsSeverity   string
	secretsOutputFmt  string
	secretsOutputFile string
)

func init() {
	secretsScanCmd.Flags().StringSliceVar(&secretsProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	secretsScanCmd.Flags().StringVar(&secretsSeverity, "severity", "LOW", "minimum severity to report")
	secretsScanCmd.Flags().StringVar(&secretsOutputFmt, "output", "table", "output format: table, json, sarif")
	secretsScanCmd.Flags().StringVar(&secretsOutputFile, "output-file", "", "write output to file")

	secretsCmd.AddCommand(secretsScanCmd)
}

func runSecretsScan(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveSecretsProviders(ctx, secretsProviders)
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

func resolveSecretsProviders(ctx context.Context, names []string) ([]cloud.SecretsProvider, error) {
	all := buildAllSecretsProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.SecretsProvider
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
	byName := make(map[string]cloud.SecretsProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.SecretsProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllSecretsProviders(ctx context.Context) []cloud.SecretsProvider {
	var providers []cloud.SecretsProvider
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
