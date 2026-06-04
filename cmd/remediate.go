package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/network"
	orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
	"github.com/nanohype/cloudgov/internal/storage"
)

var remediateCmd = &cobra.Command{
	Use:   "remediate",
	Short: "Generate fix scripts from a saved scan report",
	Long: `Read a previously-saved JSON scan report and emit shell scripts that
remediate each finding. This is the offline equivalent of "<domain> audit --fix"
— useful when you want to review findings first, gate remediation behind code
review, or apply a subset.

The expected JSON shape is whatever the corresponding scan emits via
"--output json", e.g. ` + "`cloudgov storage audit --output json --output-file storage.json`" + `.

Supported report types:
  - storage, network — each finding carries a runnable Remediation command
    (cloudgov scans populate this by default), filtered by --severity.
  - orphans — DELETE scripts are synthesized from each resource's kind+id
    (` + "`cloudgov orphans --output json`" + `). The emitted commands are destructive and
    irreversible, so review them before running. --severity does not apply.

iam findings remediate via ` + "`cloudgov iam fix`" + ` (Terraform); secrets/certs/tags
carry advisory (non-runnable) guidance surfaced in their own audit output.`,
	RunE: runRemediate,
}

var (
	remediateType   string
	remediateFrom   string
	remediateOutDir string
	remediateMinSev string
)

func init() {
	remediateCmd.Flags().StringVar(&remediateType, "type", "", "report type: storage, network, or orphans (required)")
	remediateCmd.Flags().StringVar(&remediateFrom, "from", "", "path to JSON scan report (required)")
	remediateCmd.Flags().StringVar(&remediateOutDir, "out", ".", "directory to write fix scripts")
	remediateCmd.Flags().StringVar(&remediateMinSev, "severity", "LOW", "minimum severity to include in fix scripts")
	_ = remediateCmd.MarkFlagRequired("type")
	_ = remediateCmd.MarkFlagRequired("from")
}

func runRemediate(_ *cobra.Command, _ []string) error {
	data, err := os.ReadFile(remediateFrom)
	if err != nil {
		return fmt.Errorf("read %s: %w", remediateFrom, err)
	}

	minSev := cloud.Severity(strings.ToUpper(remediateMinSev))

	switch strings.ToLower(remediateType) {
	case "storage":
		findings, err := unmarshalStorageReport(data)
		if err != nil {
			return err
		}
		findings = filterStorageBySeverity(findings, minSev)
		files, err := storage.WriteFixScripts(findings, remediateOutDir)
		if err != nil {
			return fmt.Errorf("write fix scripts: %w", err)
		}
		announceFiles(files, len(findings))
		return nil
	case "network":
		findings, err := unmarshalNetworkReport(data)
		if err != nil {
			return err
		}
		findings = filterNetworkBySeverity(findings, minSev)
		files, err := network.WriteFixScripts(findings, remediateOutDir)
		if err != nil {
			return fmt.Errorf("write fix scripts: %w", err)
		}
		announceFiles(files, len(findings))
		return nil
	case "orphans":
		orphans, err := unmarshalOrphansReport(data)
		if err != nil {
			return err
		}
		// Orphan resources have no severity; --severity does not apply.
		files, err := orphanscanner.WriteFixScripts(orphans, remediateOutDir)
		if err != nil {
			return fmt.Errorf("write fix scripts: %w", err)
		}
		announceFiles(files, len(orphans))
		return nil
	default:
		return fmt.Errorf("unsupported report type %q (want: storage, network, orphans)", remediateType)
	}
}

// storageEnvelope and networkEnvelope match the JSON output of the
// corresponding scan commands. Both have {findings: [...], total: N}.
type storageEnvelope struct {
	Findings []cloud.BucketFinding `json:"findings"`
}

type networkEnvelope struct {
	Findings []cloud.NetworkFinding `json:"findings"`
}

// orphansEnvelope matches the JSON output of "cloudgov orphans --output json",
// which wraps the resources under a "resources" key (not "findings").
type orphansEnvelope struct {
	Resources []cloud.OrphanResource `json:"resources"`
}

func unmarshalStorageReport(data []byte) ([]cloud.BucketFinding, error) {
	var env storageEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse storage report: %w", err)
	}
	if len(env.Findings) == 0 {
		// Fall back to a bare-array shape some users hand-craft.
		var bare []cloud.BucketFinding
		if err := json.Unmarshal(data, &bare); err == nil && len(bare) > 0 {
			return bare, nil
		}
	}
	return env.Findings, nil
}

func unmarshalNetworkReport(data []byte) ([]cloud.NetworkFinding, error) {
	var env networkEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse network report: %w", err)
	}
	if len(env.Findings) == 0 {
		var bare []cloud.NetworkFinding
		if err := json.Unmarshal(data, &bare); err == nil && len(bare) > 0 {
			return bare, nil
		}
	}
	return env.Findings, nil
}

func unmarshalOrphansReport(data []byte) ([]cloud.OrphanResource, error) {
	var env orphansEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse orphans report: %w", err)
	}
	if len(env.Resources) == 0 {
		var bare []cloud.OrphanResource
		if err := json.Unmarshal(data, &bare); err == nil && len(bare) > 0 {
			return bare, nil
		}
	}
	return env.Resources, nil
}

func filterStorageBySeverity(in []cloud.BucketFinding, min cloud.Severity) []cloud.BucketFinding {
	minRank := cloud.SeverityRank(min)
	out := in[:0]
	for _, f := range in {
		if cloud.SeverityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}

func filterNetworkBySeverity(in []cloud.NetworkFinding, min cloud.Severity) []cloud.NetworkFinding {
	minRank := cloud.SeverityRank(min)
	out := in[:0]
	for _, f := range in {
		if cloud.SeverityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}

func announceFiles(files []string, total int) {
	if quiet {
		return
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no remediable findings in %d input(s)\n", total)
		return
	}
	for _, f := range files {
		fmt.Fprintf(os.Stderr, "wrote fix script: %s\n", f)
	}
}
