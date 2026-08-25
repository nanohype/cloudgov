package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/spf13/cobra"
)

// Version, BuildDate, and Commit are set via ldflags at build time.
var (
	Version   = "dev"
	BuildDate = "unknown"
	Commit    = "unknown"
)

// quiet suppresses all stderr progress and summary output when true.
var quiet bool

// regions restricts regional scans to the named regions. Empty means every
// region enabled for the account.
var regions []string

// providerOptions are the options every command passes when resolving
// providers. Commands resolve through this rather than assembling the list
// themselves, so a run-scoped flag reaches every command by construction — a
// scan that silently missed one would report a narrower account than it read.
// awsProviderOptions is the same set for the two places that must construct the
// AWS provider directly rather than resolving by capability: the Platform
// auditor and its MCP handler need a concrete *cloudaws.Provider to read tenant
// IAM, which the capability interfaces do not express.
//
// It exists so those two are not the exception to the sentence above. They were:
// both called cloudaws.New with at most WithQuiet, so `--regions` was accepted,
// documented and silently ignored by `platform audit`.
func awsProviderOptions(extra ...cloudaws.Option) []cloudaws.Option {
	return append([]cloudaws.Option{
		cloudaws.WithQuiet(quiet),
		cloudaws.WithRegions(regions),
	}, extra...)
}

func providerOptions(extra ...providers.Option) []providers.Option {
	return append([]providers.Option{
		providers.WithQuiet(quiet),
		providers.WithRegions(regions),
	}, extra...)
}

var rootCmd = &cobra.Command{
	Use:   "cloudgov",
	Short: "AWS security and cost swiss army knife",
	Long: `cloudgov audits AWS infrastructure across five domains: IAM
over-privilege, cost anomalies, infrastructure hygiene (orphans,
storage, network, certs, tags), security posture (secrets, compliance,
drift, full audit), and operational visibility (inventory, quotas,
baselines, diffs, reports).`,
	SilenceUsage: true,
	// Reset run-scoped state before every command so the tree is safe to drive
	// repeatedly in one process, and refuse a --fail-on this tool cannot rank.
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		resetRunState(cmd)

		// An unrecognised threshold does not fail loudly, it ranks 0 — below
		// every real level — so `--fail-on HIHG` sets the bar at nothing and the
		// first INFO finding exits 2. A gate that fails for a reason nobody
		// intended teaches its operator to stop believing it, which costs more
		// than the typo.
		if _, err := resolveSeverity(failOn, ""); err != nil {
			return fmt.Errorf("--fail-on: %w", err)
		}
		return nil
	},
}

// Execute runs the root command under a context cancelled on the first
// SIGINT/SIGTERM, so an interrupt unwinds in-flight cloud API calls — which all
// take cmd.Context() — instead of leaving them to run to completion.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

func init() {
	rootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress and summary output to stderr")
	rootCmd.PersistentFlags().StringVar(&failOn, "fail-on", "",
		"exit with code 2 if any finding is at or above this "+severityUsage("severity"))
	rootCmd.PersistentFlags().StringSliceVar(&regions, "regions", nil, "regions to scan for regional resources (default: every region enabled for the account)")
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(iamCmd)
	rootCmd.AddCommand(costCmd)
	rootCmd.AddCommand(orphansCmd)
	rootCmd.AddCommand(storageCmd)
	rootCmd.AddCommand(repoCmd)
	rootCmd.AddCommand(networkCmd)
	rootCmd.AddCommand(certsCmd)
	rootCmd.AddCommand(tagsCmd)
	rootCmd.AddCommand(secretsCmd)
	rootCmd.AddCommand(complianceCmd)
	rootCmd.AddCommand(driftCmd)
	rootCmd.AddCommand(inventoryCmd)
	rootCmd.AddCommand(quotaCmd)
	rootCmd.AddCommand(baselineCmd)
	rootCmd.AddCommand(compareCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(k8sCmd)
	rootCmd.AddCommand(remediateCmd)
	rootCmd.AddCommand(lambdaCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(platformCmd)
}
