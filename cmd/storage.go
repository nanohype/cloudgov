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
	"github.com/nanohype/cloudgov/internal/storage"
)

var storageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Object storage security audit",
}

var storageAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit buckets for public access, encryption, versioning, and logging",
	RunE:  runStorageAudit,
}

var (
	storageProviders  []string
	storageSeverity   string
	storageOutputFmt  string
	storageOutputFile string
	storageFix        bool
	storageOutDir     string
)

func init() {
	storageAuditCmd.Flags().StringSliceVar(&storageProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	storageAuditCmd.Flags().StringVar(&storageSeverity, "severity", "LOW", "minimum severity to report")
	storageAuditCmd.Flags().StringVar(&storageOutputFmt, "output", "table", "output format: table, json, sarif")
	storageAuditCmd.Flags().StringVar(&storageOutputFile, "output-file", "", "write output to file")
	storageAuditCmd.Flags().BoolVar(&storageFix, "fix", false, "generate shell remediation scripts for each finding")
	storageAuditCmd.Flags().StringVar(&storageOutDir, "out", ".", "directory to write fix scripts (used with --fix)")

	storageCmd.AddCommand(storageAuditCmd)
}

func runStorageAudit(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveStorageProviders(ctx, storageProviders)
	if err != nil {
		return err
	}

	findings, err := storage.Scan(ctx, providers, storage.ScanOptions{
		MinSeverity: cloud.Severity(strings.ToUpper(storageSeverity)),
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if storageOutputFile != "" {
		f, err := os.Create(storageOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(storageOutputFmt) {
	case "json":
		return output.WriteStorage(w, findings)
	case "sarif":
		return output.WriteStorageSARIF(w, findings, Version)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d storage findings\n\n", len(findings))
		}
		output.BucketFindings(w, findings)
	}

	if storageFix {
		files, err := storage.WriteFixScripts(findings, storageOutDir)
		if err != nil {
			return fmt.Errorf("write fix scripts: %w", err)
		}
		if !quiet {
			for _, f := range files {
				fmt.Fprintf(os.Stderr, "wrote fix script: %s\n", f)
			}
		}
	}
	return nil
}

func resolveStorageProviders(ctx context.Context, names []string) ([]cloud.StorageProvider, error) {
	all := buildAllStorageProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.StorageProvider
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
	byName := make(map[string]cloud.StorageProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.StorageProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllStorageProviders(ctx context.Context) []cloud.StorageProvider {
	var providers []cloud.StorageProvider
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
