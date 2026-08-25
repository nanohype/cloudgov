package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/nanohype/cloudgov/internal/cloud"
	cloudk8s "github.com/nanohype/cloudgov/internal/cloud/k8s"
	"github.com/nanohype/cloudgov/internal/output"
)

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Kubernetes cluster security audits",
}

var k8sRBACCmd = &cobra.Command{
	Use:   "rbac",
	Short: "Find over-privileged ClusterRoles and broad ClusterRoleBindings",
	Long: `Scan cluster-scoped RBAC for the patterns that cause real incidents:

  - ClusterRoles with verbs:["*"] on resources:["*"]
  - ClusterRoles with wildcard verbs on any resource
  - ClusterRoles with dangerous verbs (create/update/patch/delete) on
    wildcard resources
  - ClusterRoleBindings to broad groups (system:authenticated,
    system:unauthenticated, system:masters)
  - ClusterRoleBindings to cluster-admin (any subject)

Built-in default ClusterRoles (cluster-admin, admin, edit, view,
system:*, kubeadm:*) are skipped — only custom roles are reported.`,
	RunE: runK8sRBAC,
}

var (
	k8sKubeconfig  string
	k8sOutputFmt   string
	k8sOutputFile  string
	k8sMinSeverity string
)

func init() {
	k8sCmd.PersistentFlags().StringVar(&k8sKubeconfig, "kubeconfig", "",
		"path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config, falls back to in-cluster)")
	k8sCmd.PersistentFlags().StringVar(&k8sOutputFmt, "output", tableJSONSARIF[0], tableJSONSARIF.usage())
	k8sCmd.PersistentFlags().StringVar(&k8sOutputFile, "output-file", "", "write output to file instead of stdout")
	k8sCmd.PersistentFlags().StringVar(&k8sMinSeverity, "severity", "LOW", severityUsage("minimum severity to report"))

	k8sCmd.AddCommand(k8sRBACCmd)
}

func runK8sRBAC(cmd *cobra.Command, _ []string) error {
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	k8sFormat, err := tableJSONSARIF.resolve(k8sOutputFmt)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	p, err := cloudk8s.New(ctx, k8sKubeconfig)
	if err != nil {
		return fmt.Errorf("connect to kubernetes: %w", err)
	}

	findings, err := p.ScanRBAC(ctx)
	if err != nil {
		return err
	}

	// RBAC has no partial state to report. Both reads it makes — cluster roles
	// and cluster role bindings — return an error rather than a short list, so a
	// denied read fails the command instead of yielding a clean-looking scan.
	// The record is emitted anyway: an absent incomplete field and an empty one
	// are different claims, and this is the empty one.
	k8sUnread := []string{}

	minSeverity, err := resolveSeverity(k8sMinSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	findings = filterK8sBySeverity(findings, minSeverity)

	gate(findings, func(f cloud.K8sFinding) cloud.Severity { return f.Severity })

	w, closer, err := openK8sOutput()
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	switch k8sFormat {
	case "json":
		return output.WriteK8sFindings(w, findings, k8sUnread)
	case "sarif":
		return output.WriteK8sSARIF(w, findings, Version, k8sUnread)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d RBAC findings (context: %s)\n\n", len(findings), p.ContextName())
		}
		output.K8sFindings(w, findings)
	}
	return nil
}

func openK8sOutput() (out *os.File, closer func(), err error) {
	if k8sOutputFile == "" {
		return os.Stdout, nil, nil
	}
	f, err := os.Create(k8sOutputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

// The threshold arrives already validated. Casting a raw flag here instead
// would rank an unrecognised level 0, and every real level outranks 0 — so a
// typo widens this filter to everything rather than failing.
func filterK8sBySeverity(in []cloud.K8sFinding, min cloud.Severity) []cloud.K8sFinding {
	minRank := cloud.SeverityRank(min)
	out := in[:0]
	for _, f := range in {
		if cloud.SeverityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}
