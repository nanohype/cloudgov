package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/nanohype/cloudgov/internal/quota"
	"github.com/spf13/cobra"
)

var quotaCmd = &cobra.Command{
	Use:   "quota",
	Short: "Check service quota utilization across cloud providers",
	RunE:  runQuota,
}

var (
	quotaThreshold  float64
	quotaOutputFmt  string
	quotaOutputFile string
)

func init() {
	quotaCmd.Flags().Float64Var(&quotaThreshold, "threshold", 0, "minimum utilization percentage to report")
	quotaCmd.Flags().StringVar(&quotaOutputFmt, "output", "table", "output format: table, json")
	quotaCmd.Flags().StringVar(&quotaOutputFile, "output-file", "", "write output to file")
}

func runQuota(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveQuotaProviders(ctx)
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "scanning quotas across %d provider(s)...\n", len(providers))
	}

	quotas, err := quota.Scan(ctx, providers, quota.ScanOptions{
		MinUtilization: quotaThreshold,
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if quotaOutputFile != "" {
		f, err := os.Create(quotaOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch strings.ToLower(quotaOutputFmt) {
	case "json":
		return output.WriteQuotas(w, quotas)
	default:
		summary := quota.Summarize(quotas)
		if !quiet {
			fmt.Fprintf(os.Stderr, "\n%d quotas: %d critical, %d high, %d medium\n\n",
				summary.Total, summary.Critical, summary.High, summary.Medium)
		}
		output.QuotaUsages(w, quotas)
	}
	return nil
}

func resolveQuotaProviders(ctx context.Context) ([]cloud.QuotaProvider, error) {
	return providers.Resolve[cloud.QuotaProvider](ctx, providers.WithQuiet(quiet))
}
