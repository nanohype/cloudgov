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
	"github.com/nanohype/cloudgov/internal/quota"
)

var quotaCmd = &cobra.Command{
	Use:   "quota",
	Short: "Check service quota utilization across cloud providers",
	RunE:  runQuota,
}

var (
	quotaProviders  []string
	quotaThreshold  float64
	quotaOutputFmt  string
	quotaOutputFile string
)

func init() {
	quotaCmd.Flags().StringSliceVar(&quotaProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	quotaCmd.Flags().Float64Var(&quotaThreshold, "threshold", 0, "minimum utilization percentage to report")
	quotaCmd.Flags().StringVar(&quotaOutputFmt, "output", "table", "output format: table, json")
	quotaCmd.Flags().StringVar(&quotaOutputFile, "output-file", "", "write output to file")
}

func runQuota(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	providers, err := resolveQuotaProviders(ctx, quotaProviders)
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
		defer f.Close()
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

func resolveQuotaProviders(ctx context.Context, names []string) ([]cloud.QuotaProvider, error) {
	all := buildAllQuotaProviders(ctx)
	if len(names) == 0 {
		var detected []cloud.QuotaProvider
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
	byName := make(map[string]cloud.QuotaProvider)
	for _, p := range all {
		byName[p.Name()] = p
	}
	var result []cloud.QuotaProvider
	for _, name := range names {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider: %s", name)
		}
		result = append(result, p)
	}
	return result, nil
}

func buildAllQuotaProviders(ctx context.Context) []cloud.QuotaProvider {
	var providers []cloud.QuotaProvider
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
