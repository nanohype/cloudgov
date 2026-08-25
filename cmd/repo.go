package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/repo"
)

var repoCmd = &cobra.Command{
	Use:   "repo",
	Short: "Audit GitHub repository settings against the committed expected shape",
}

var repoAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Report repositories whose settings differ from expected-repo-settings.yaml",
	Long: `Compare every repository in the org against a committed expected shape.

Branch protection, required checks and Dependabot state live only in GitHub. No
gate inside a repository can observe them, so a repo can carry a full CI matrix,
a protection rule that requires none of it, and nothing anywhere will say so.

What this reports:

  - a default branch with no protection rule
  - a protection rule requiring ZERO status checks — the most misleading of the
    three, since the repository reads as protected everywhere while admitting a
    PR whose entire CI matrix is red
  - expected checks absent from the required set
  - enforce_admins off, force pushes or branch deletion allowed
  - Dependabot alerts disabled, security updates disabled, or alerts left open
  - protection unavailable on the current plan, which no setting fixes and which
    is reported rather than passed over so the exposure is stated

Reported, never enforced. Reading uses the gh CLI's existing credential, the same
way the AWS commands use the ambient credential chain.`,
	RunE: runRepoAudit,
}

var (
	repoOrg          string
	repoExpectedFile string
	repoOutputFmt    string
	repoOutputFile   string
	repoSeverity     string
)

func init() {
	// No default organization. A default here does not save a keystroke, it picks
	// a target: `gh repo list` succeeds against any public org, so a bare
	// `cloudgov repo audit` would sweep whichever organization was compiled in
	// and report findings about repositories the caller does not own.
	repoCmd.PersistentFlags().StringVar(&repoOrg, "org", "", "GitHub organization to audit")
	repoCmd.PersistentFlags().StringVar(&repoExpectedFile, "expected", "expected-repo-settings.yaml",
		"path to the committed expected settings")
	repoCmd.PersistentFlags().StringVar(&repoOutputFmt, "output", tableJSON[0], tableJSON.usage())
	repoCmd.PersistentFlags().StringVar(&repoOutputFile, "output-file", "", "write output to a file instead of stdout")
	repoCmd.PersistentFlags().StringVar(&repoSeverity, "severity", "LOW", "minimum severity to report")

	// Marked required so cobra rejects the omission by name. Without this an
	// empty org reaches checkName and fails with `org "" is not a valid GitHub
	// name`, which describes the value rather than the missing flag.
	_ = repoCmd.MarkPersistentFlagRequired("org")

	repoCmd.AddCommand(repoAuditCmd)
}

func runRepoAudit(cmd *cobra.Command, _ []string) error {
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	repoFormat, err := tableJSON.resolve(repoOutputFmt)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(repoExpectedFile)
	if err != nil {
		return fmt.Errorf("read expected settings: %w", err)
	}
	var exp repo.Expected
	if err := yaml.Unmarshal(raw, &exp); err != nil {
		return fmt.Errorf("parse %s: %w", repoExpectedFile, err)
	}

	findings, err := repo.Audit(cmd.Context(), repo.NewGHReader(), repoOrg, exp)
	if err != nil {
		return err
	}

	minRank := cloud.SeverityRank(cloud.Severity(strings.ToUpper(repoSeverity)))
	var kept []cloud.RepoFinding
	for _, f := range findings {
		if cloud.SeverityRank(f.Severity) >= minRank {
			kept = append(kept, f)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].Repo != kept[j].Repo {
			return kept[i].Repo < kept[j].Repo
		}
		return kept[i].Type < kept[j].Type
	})

	w := cmd.OutOrStdout()
	if repoOutputFile != "" {
		f, err := os.Create(repoOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if repoFormat == "json" {
		return output.WriteRepo(w, kept)
	}
	output.RepoFindings(w, kept)
	return nil
}
