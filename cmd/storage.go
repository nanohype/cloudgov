package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
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
	storageAuditCmd.Flags().StringVar(&storageOutputFmt, "output", tableJSONSARIF[0], tableJSONSARIF.usage())
	storageAuditCmd.Flags().StringVar(&storageOutputFile, "output-file", "", "write output to file")
	storageAuditCmd.Flags().BoolVar(&storageFix, "fix", false, "generate shell remediation scripts for each finding")
	storageAuditCmd.Flags().StringVar(&storageOutDir, "out", ".", "directory to write fix scripts (used with --fix)")

	storageCmd.AddCommand(storageAuditCmd)
}

func runStorageAudit(cmd *cobra.Command, _ []string) error {
	// Refused rather than coerced: an unrecognised level ranks below every
	// real one, so a typo widens a reporting floor instead of failing.
	minSeverity, err := resolveSeverity(storageSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	storageFormat, err := tableJSONSARIF.resolve(storageOutputFmt)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	providers, err := resolveStorageProviders(ctx)
	if err != nil {
		return err
	}

	findings, err := storage.Scan(ctx, providers, storage.ScanOptions{
		MinSeverity: minSeverity,
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
		defer func() { _ = f.Close() }()
		w = f
	}

	incomplete := cloud.Incomplete(providers)
	gate(findings, func(f cloud.BucketFinding) cloud.Severity { return f.Severity })
	gateIncomplete(incomplete)

	switch storageFormat {
	case "json":
		return output.WriteStorage(w, findings, incomplete)
	case "sarif":
		return output.WriteStorageSARIF(w, findings, Version, incomplete)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d storage findings\n\n", len(findings))
		}
		output.BucketFindings(w, findings)
		output.IncompleteNote(w, incomplete)
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
	return providers.Resolve[cloud.StorageProvider](ctx, providerOptions()...)
}
