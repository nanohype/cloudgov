package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	cloudk8s "github.com/nanohype/cloudgov/internal/cloud/k8s"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/platform"
)

var platformCmd = &cobra.Command{
	Use:   "platform",
	Short: "Audit nanohype Platform tenants against the eks-agent-platform contract",
}

var platformAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Verify live Platform tenants conform to their contract",
	Long: `Read every Platform CR (platform.nanohype.dev/v1alpha1) in the cluster and check
that its deployed state still matches the eks-agent-platform contract:

  - tenant namespace exists with PSS=restricted and ownership labels
  - tenant-default ResourceQuota and LimitRange are present
  - tenant-egress NetworkPolicy is present, egress-typed, and namespace-wide
  - tenant-runtime ServiceAccount carries the IRSA role-arn annotation that
    matches Platform.status.iamRoleArn
  - the IAM role behind status.iamRoleArn exists, trusts only the tenant
    ServiceAccount, has no inline policies, carries the declared
    extraPolicyArns, and its suspension tag agrees with status (needs AWS creds)
  - spec.identity declares exactly one of allowedModels / allowedModelFamilies
  - spec.budget.name resolves to a BudgetPolicy; SOC2 platforms have the
    budget kill-switch enabled
  - the Platform's compliance is at least as strict as its owning Tenant

cloudgov only reports — the operator enforces. This catches drift, manual
tampering, and reconcile gaps. Platforms that are not yet Ready are skipped
with an informational note.`,
	RunE: runPlatformAudit,
}

var (
	platformKubeconfig string
	platformOutputFmt  string
	platformOutputFile string
	platformSeverity   string
)

func init() {
	platformCmd.PersistentFlags().StringVar(&platformKubeconfig, "kubeconfig", "",
		"path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config, falls back to in-cluster)")
	platformCmd.PersistentFlags().StringVar(&platformOutputFmt, "output", "table", "output format: table, json, sarif")
	platformCmd.PersistentFlags().StringVar(&platformOutputFile, "output-file", "", "write output to file instead of stdout")
	platformCmd.PersistentFlags().StringVar(&platformSeverity, "severity", "LOW", "minimum severity to report")

	platformCmd.AddCommand(platformAuditCmd)
}

func runPlatformAudit(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	clients, err := cloudk8s.NewClients(ctx, platformKubeconfig)
	if err != nil {
		return fmt.Errorf("connect to kubernetes: %w", err)
	}

	// AWS IRSA conformance needs AWS credentials; skip it (with a note) when
	// they're absent so the k8s-side audit still runs.
	var roles platform.RoleReader
	if awsP, aerr := cloudaws.New(ctx, cloudaws.WithQuiet(quiet)); aerr == nil && awsP.Detect(ctx) {
		roles = awsP
	} else if !quiet {
		fmt.Fprintln(os.Stderr, "note: AWS credentials not detected; skipping IRSA role conformance")
	}

	findings, err := platform.Audit(ctx, clients.Typed, clients.Dynamic, roles)
	if err != nil {
		return err
	}
	findings = filterPlatformBySeverity(findings, strings.ToUpper(platformSeverity))
	gate(findings, func(f cloud.PlatformFinding) cloud.Severity { return f.Severity })

	w := os.Stdout
	if platformOutputFile != "" {
		file, err := os.Create(platformOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = file.Close() }()
		w = file
	}

	switch strings.ToLower(platformOutputFmt) {
	case "json":
		return output.WritePlatform(w, findings)
	case "sarif":
		return output.WritePlatformSARIF(w, findings, Version)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d platform conformance findings (context: %s)\n\n", len(findings), clients.ContextName)
		}
		output.PlatformFindings(w, findings)
	}
	return nil
}

func filterPlatformBySeverity(in []cloud.PlatformFinding, min string) []cloud.PlatformFinding {
	minRank := cloud.SeverityRank(cloud.Severity(min))
	out := in[:0]
	for _, f := range in {
		if cloud.SeverityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}
