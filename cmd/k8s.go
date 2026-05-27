package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stxkxs/matlock/internal/cloud"
	cloudk8s "github.com/stxkxs/matlock/internal/cloud/k8s"
	"github.com/stxkxs/matlock/internal/output"
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
	k8sCmd.PersistentFlags().StringVar(&k8sOutputFmt, "output", "table", "output format: table, json")
	k8sCmd.PersistentFlags().StringVar(&k8sOutputFile, "output-file", "", "write output to file instead of stdout")
	k8sCmd.PersistentFlags().StringVar(&k8sMinSeverity, "severity", "LOW", "minimum severity to report")

	k8sCmd.AddCommand(k8sRBACCmd)
}

func runK8sRBAC(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	p, err := cloudk8s.New(ctx, k8sKubeconfig)
	if err != nil {
		return fmt.Errorf("connect to kubernetes: %w", err)
	}

	findings, err := p.ScanRBAC(ctx)
	if err != nil {
		return err
	}

	findings = filterK8sBySeverity(findings, strings.ToUpper(k8sMinSeverity))

	w, closer, err := openK8sOutput()
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	switch strings.ToLower(k8sOutputFmt) {
	case "json":
		return output.WriteK8sFindings(w, findings)
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

func filterK8sBySeverity(in []cloud.K8sFinding, min string) []cloud.K8sFinding {
	minRank := cloud.SeverityRank(cloud.Severity(min))
	out := in[:0]
	for _, f := range in {
		if cloud.SeverityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}
