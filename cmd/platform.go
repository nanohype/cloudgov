package cmd

import (
	"fmt"
	"os"

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
  - the ServiceAccount the Pod Identity association binds exists and carries no
    eks.amazonaws.com/role-arn annotation (the contract forbids it — the
    association is the binding, not a pasted ARN)
  - the IAM role behind status.iamRoleArn exists, trusts the EKS Pod Identity
    service principal, carries the operator's generated inline policies and
    nothing hand-attached, carries the declared extraPolicyArns, and its
    suspension tag agrees with status (needs AWS creds)
  - an EKS Pod Identity association binds the tenant ServiceAccount to that same
    role — the association is where tenancy lives, since a Pod Identity trust
    policy carries no subject and is identical for every tenant (needs AWS creds)
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
	platformCmd.PersistentFlags().StringVar(&platformOutputFmt, "output", tableJSONSARIF[0], tableJSONSARIF.usage())
	platformCmd.PersistentFlags().StringVar(&platformOutputFile, "output-file", "", "write output to file instead of stdout")
	platformCmd.PersistentFlags().StringVar(&platformSeverity, "severity", "LOW", "minimum severity to report")

	platformCmd.AddCommand(platformAuditCmd)
}

func runPlatformAudit(cmd *cobra.Command, _ []string) error {
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	platformFormat, err := tableJSONSARIF.resolve(platformOutputFmt)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	clients, err := cloudk8s.NewClients(ctx, platformKubeconfig)
	if err != nil {
		return fmt.Errorf("connect to kubernetes: %w", err)
	}

	// The tenant-role and Pod Identity checks need AWS credentials; skip them
	// when they're absent so the k8s-side audit still runs. Absent credentials
	// are an incomplete observation rather than a note: the run did not perform a
	// whole class of conformance checks, and a reader who cannot tell that from a
	// clean report has been told the tenant conforms when half of it went
	// unexamined.
	var roles platform.IdentityReader
	var awsProviders []*cloudaws.Provider
	if awsP, aerr := cloudaws.New(ctx, cloudaws.WithQuiet(quiet)); aerr == nil && awsP.Detect(ctx) {
		roles = awsP
		awsProviders = append(awsProviders, awsP)
	}

	findings, unread, err := platform.Audit(ctx, clients.Typed, clients.Dynamic, roles)
	if err != nil {
		return err
	}
	minSeverity, err := resolveSeverity(platformSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	findings = filterPlatformBySeverity(findings, minSeverity)

	// Warnings raised while reading tenant roles accumulate on the provider and
	// are only a record if something reads them. The cluster side has no
	// provider to accumulate on, so the auditor returns its own unread list;
	// both are the same fact and both must survive the severity filter above.
	incomplete := append(cloud.Incomplete(awsProviders), unread...)
	if roles == nil {
		incomplete = append(incomplete,
			"AWS credentials not detected; tenant-role and Pod Identity conformance were not checked")
	}

	gate(findings, func(f cloud.PlatformFinding) cloud.Severity { return f.Severity })
	gateIncomplete(incomplete)

	w := os.Stdout
	if platformOutputFile != "" {
		file, err := os.Create(platformOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = file.Close() }()
		w = file
	}

	switch platformFormat {
	case "json":
		return output.WritePlatform(w, findings, incomplete)
	case "sarif":
		return output.WritePlatformSARIF(w, findings, Version, incomplete)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d platform conformance findings (context: %s)\n\n", len(findings), clients.ContextName)
		}
		output.PlatformFindings(w, findings)
		output.IncompleteNote(w, incomplete)
	}
	return nil
}

// The threshold arrives already validated. Casting a raw flag here instead
// would rank an unrecognised level 0, and every real level outranks 0 — so a
// typo widens this filter to everything rather than failing.
func filterPlatformBySeverity(in []cloud.PlatformFinding, min cloud.Severity) []cloud.PlatformFinding {
	minRank := cloud.SeverityRank(min)
	out := in[:0]
	for _, f := range in {
		if cloud.SeverityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}
