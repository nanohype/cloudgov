package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	cloudazure "github.com/nanohype/cloudgov/internal/cloud/azure"
	cloudgcp "github.com/nanohype/cloudgov/internal/cloud/gcp"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/fix"
	"github.com/nanohype/cloudgov/internal/iam"
	"github.com/nanohype/cloudgov/internal/output"
)

var iamCmd = &cobra.Command{
	Use:   "iam",
	Short: "IAM least-privilege analysis",
}

var iamScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan principals for unused and overprivileged permissions",
	RunE:  runIAMScan,
}

var iamFixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Generate minimal policy fix files from a prior scan report",
	RunE:  runIAMFix,
}

var (
	iamProviders   []string
	iamDays        int
	iamPrincipal   string
	iamSeverity    string
	iamOutputFmt   string
	iamOutputFile  string
	iamConcurrency int
	iamProfile     string
	iamFromFile    string
	iamFixFormat   string
	iamFixOut      string
	iamFixSeverity string
)

func init() {
	iamScanCmd.Flags().StringSliceVar(&iamProviders, "provider", []string{}, "cloud providers to scan (aws,gcp,azure); auto-detect if empty")
	iamScanCmd.Flags().IntVar(&iamDays, "days", 90, "audit log lookback period in days")
	iamScanCmd.Flags().StringVar(&iamPrincipal, "principal", "", "scan a specific principal by name or ID")
	iamScanCmd.Flags().StringVar(&iamSeverity, "severity", "LOW", "minimum severity to report (CRITICAL,HIGH,MEDIUM,LOW,INFO)")
	iamScanCmd.Flags().StringVar(&iamOutputFmt, "output", "table", "output format: table, json, sarif")
	iamScanCmd.Flags().StringVar(&iamOutputFile, "output-file", "", "write output to file instead of stdout")
	iamScanCmd.Flags().IntVar(&iamConcurrency, "concurrency", 10, "max parallel goroutines for scanning principals")
	iamScanCmd.Flags().StringVar(&iamProfile, "profile", "", "AWS named profile to use for credentials")

	iamFixCmd.Flags().StringVar(&iamFromFile, "from", "", "path to JSON report from 'cloudgov iam scan --output json'")
	iamFixCmd.Flags().StringVar(&iamFixFormat, "format", "terraform", "fix format: terraform, json")
	iamFixCmd.Flags().StringVar(&iamFixOut, "out", "./cloudgov-fixes", "output directory")
	iamFixCmd.Flags().StringVar(&iamFixSeverity, "severity", "HIGH", "minimum severity to generate fixes for")
	_ = iamFixCmd.MarkFlagRequired("from")

	iamCmd.AddCommand(iamScanCmd, iamFixCmd)
}

func runIAMScan(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveIAMProviders(ctx, iamProviders, iamProfile)
	if err != nil {
		return err
	}

	opts := iam.ScanOptions{
		Days:            iamDays,
		PrincipalFilter: iamPrincipal,
		MinSeverity:     cloud.Severity(strings.ToUpper(iamSeverity)),
		Concurrency:     iamConcurrency,
	}

	var allFindings []cloud.Finding
	allUsedPerms := make(map[string][]cloud.Permission)
	totalPrincipals := 0
	for _, p := range providers {
		providerName := p.Name()
		if !quiet {
			opts.Progress = func(done, total int) {
				fmt.Fprintf(os.Stderr, "\rscanning %s: %d/%d principals...", providerName, done, total)
				if done == total {
					fmt.Fprintln(os.Stderr)
				}
			}
		}
		result, err := iam.Scan(ctx, p, opts)
		if err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "warn: %s scan failed: %v\n", p.Name(), err)
			}
			continue
		}
		allFindings = append(allFindings, result.Findings...)
		totalPrincipals += result.Principals
		for pid, used := range result.UsedPermissions {
			allUsedPerms[pid] = used
		}
	}

	w := os.Stdout
	if iamOutputFile != "" {
		f, err := os.Create(iamOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(iamOutputFmt) {
	case "json":
		return output.WriteIAM(w, allFindings, totalPrincipals, allUsedPerms)
	case "sarif":
		return output.WriteSARIF(w, allFindings, Version)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d findings across %d principals\n\n", len(allFindings), totalPrincipals)
		}
		output.IAMFindings(w, allFindings, totalPrincipals)
	}
	return nil
}

func runIAMFix(_ *cobra.Command, _ []string) error {
	ctx := context.Background()

	data, err := os.ReadFile(iamFromFile)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}

	type report struct {
		Findings        []cloud.Finding                `json:"findings"`
		UsedPermissions map[string][]cloud.Permission  `json:"used_permissions"`
	}
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}

	// Build minimal policies for each unique principal
	providers, err := resolveIAMProviders(ctx, nil, "")
	if err != nil {
		return err
	}

	providerMap := make(map[string]cloud.IAMProvider)
	for _, p := range providers {
		providerMap[p.Name()] = p
	}

	policies := make(map[string]cloud.Policy)
	for _, f := range r.Findings {
		if f.Principal == nil {
			continue
		}
		if _, ok := policies[f.Principal.ID]; ok {
			continue
		}
		p, ok := providerMap[f.Provider]
		if !ok {
			continue
		}
		usedPerms := r.UsedPermissions[f.Principal.ID]
		pol, err := p.MinimalPolicy(ctx, *f.Principal, usedPerms)
		if err != nil {
			continue
		}
		policies[f.Principal.ID] = pol
	}

	opts := fix.Options{
		OutputDir: iamFixOut,
		Severity:  cloud.Severity(strings.ToUpper(iamFixSeverity)),
	}

	switch strings.ToLower(iamFixFormat) {
	case "json":
		return fix.WriteRawPolicies(policies, opts.OutputDir)
	default:
		if err := fix.GenerateTerraform(r.Findings, policies, opts); err != nil {
			return err
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "fix files written to %s\n", opts.OutputDir)
		}
	}
	return nil
}

func resolveIAMProviders(ctx context.Context, names []string, profile string) ([]cloud.IAMProvider, error) {
	all := buildAllIAMProviders(ctx, profile)
	if len(names) == 0 {
		// Auto-detect
		var detected []cloud.IAMProvider
		for _, p := range all {
			if p.Detect(ctx) {
				detected = append(detected, p)
			}
		}
		if len(detected) == 0 {
			return nil, fmt.Errorf("no cloud provider credentials detected; set AWS_PROFILE, GOOGLE_CLOUD_PROJECT, or AZURE_SUBSCRIPTION_ID")
		}
		return detected, nil
	}

	byName := make(map[string]cloud.IAMProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.IAMProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllIAMProviders(ctx context.Context, profile string) []cloud.IAMProvider {
	var providers []cloud.IAMProvider
	if p, err := cloudaws.NewWithProfile(ctx, profile); err == nil {
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
