package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/storage"
	"github.com/spf13/cobra"
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
	storageSeverity   string
	storageOutputFmt  string
	storageOutputFile string
	storageFix        bool
	storageOutDir     string
)

func init() {
	storageAuditCmd.Flags().StringVar(&storageSeverity, "severity", "LOW", "minimum severity to report")
	storageAuditCmd.Flags().StringVar(&storageOutputFmt, "output", "table", "output format: table, json, sarif")
	storageAuditCmd.Flags().StringVar(&storageOutputFile, "output-file", "", "write output to file")
	storageAuditCmd.Flags().BoolVar(&storageFix, "fix", false, "generate shell remediation scripts for each finding")
	storageAuditCmd.Flags().StringVar(&storageOutDir, "out", ".", "directory to write fix scripts (used with --fix)")

	storageCmd.AddCommand(storageAuditCmd)
}

func runStorageAudit(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveStorageProviders(ctx)
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

func resolveStorageProviders(ctx context.Context) ([]cloud.StorageProvider, error) {
	p, err := cloudaws.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize aws: %w", err)
	}
	if !p.Detect(ctx) {
		return nil, fmt.Errorf("no AWS credentials detected")
	}
	return []cloud.StorageProvider{p}, nil
}
