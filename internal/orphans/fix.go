package orphans

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// WriteFixScripts generates an executable shell script per provider that DELETES
// the orphaned resources in the report, written to outDir as
// delete-orphans-<provider>.sh. Only orphan kinds with a known single-command
// delete path are included; kinds without one (or with an empty identifier) are
// skipped, so the script never emits a half-formed command. Returns the files
// written (one per provider that had at least one deletable orphan).
//
// The scripts are generate-then-review-then-run by design: deletes are
// irreversible, so cloudgov emits the commands for inspection rather than calling
// the delete APIs itself. Output is deterministic (no embedded timestamp) and the
// write is diff-aware — a script whose contents already match what is on disk is
// left untouched, so re-running remediate is idempotent and won't clobber a file
// that hasn't changed.
func WriteFixScripts(orphans []cloud.OrphanResource, outDir string) ([]string, error) {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	byProvider := make(map[string][]cloud.OrphanResource)
	for _, o := range orphans {
		if deleteCommand(o) == "" {
			continue // no known single-command delete for this kind
		}
		byProvider[o.Provider] = append(byProvider[o.Provider], o)
	}

	var written []string
	for provider, porphans := range byProvider {
		path := filepath.Join(outDir, fmt.Sprintf("delete-orphans-%s.sh", provider))
		if err := writeIfChanged(path, providerScript(provider, porphans)); err != nil {
			return written, fmt.Errorf("write %s: %w", path, err)
		}
		written = append(written, path)
	}
	return written, nil
}

func providerScript(provider string, orphans []cloud.OrphanResource) []byte {
	var sb strings.Builder

	sb.WriteString("#!/usr/bin/env bash\n")
	sb.WriteString("set -euo pipefail\n\n")
	sb.WriteString("# cloudgov remediate --type orphans\n")
	fmt.Fprintf(&sb, "# Provider: %s\n", provider)
	fmt.Fprintf(&sb, "# Resources: %d\n", len(orphans))
	sb.WriteString("#\n")
	sb.WriteString("# DESTRUCTIVE: each command below DELETES a resource cloudgov flagged as\n")
	sb.WriteString("# orphaned. Review every line before running; deletes are irreversible.\n\n")

	for _, o := range orphans {
		fmt.Fprintf(&sb, "# [%s] %s", o.Kind, o.Name)
		if o.Region != "" {
			fmt.Fprintf(&sb, " (%s)", o.Region)
		}
		sb.WriteString("\n")
		if o.Detail != "" {
			fmt.Fprintf(&sb, "# %s\n", o.Detail)
		}
		sb.WriteString(deleteCommand(o))
		sb.WriteString("\n\n")
	}

	return []byte(sb.String())
}

// deleteCommand returns the shell command(s) that delete an orphan, or "" if the
// kind has no known single-command delete path. Identifiers are single-quoted; AWS
// resource IDs never contain shell metacharacters, but quoting keeps the generated
// script correct for any input. Deregistering an AMI leaves its backing snapshots,
// which a subsequent scan flags as stranded snapshots.
func deleteCommand(o cloud.OrphanResource) string {
	if o.ID == "" {
		return ""
	}
	id := shellQuote(o.ID)
	region := regionFlag(o.Region)
	switch o.Kind {
	case cloud.OrphanDisk:
		return "aws ec2 delete-volume --volume-id " + id + region
	case cloud.OrphanIP:
		return "aws ec2 release-address --allocation-id " + id + region
	case cloud.OrphanLoadBalancer:
		return "aws elbv2 delete-load-balancer --load-balancer-arn " + id + region
	case cloud.OrphanSnapshot:
		return "aws ec2 delete-snapshot --snapshot-id " + id + region
	case cloud.OrphanImage:
		return "aws ec2 deregister-image --image-id " + id + region
	case cloud.OrphanEKSLogGroup:
		return "aws logs delete-log-group --log-group-name " + id + region
	case cloud.OrphanKarpenterQueue:
		return "aws sqs delete-queue --queue-url " + id + region
	case cloud.OrphanKarpenterRule:
		return karpenterRuleDelete(o, region)
	default:
		return ""
	}
}

// karpenterRuleDelete emits the two-step EventBridge rule teardown: a rule with
// targets can't be deleted until its targets are removed. delete-rule and
// remove-targets are keyed by rule NAME (not ARN), so it uses o.Name; an empty
// name means there's no safe delete path, so it returns "".
func karpenterRuleDelete(o cloud.OrphanResource, region string) string {
	if o.Name == "" {
		return ""
	}
	name := shellQuote(o.Name)
	var sb strings.Builder
	fmt.Fprintf(&sb, "_ids=$(aws events list-targets-by-rule --rule %s%s --query 'Targets[].Id' --output text)\n", name, region)
	sb.WriteString("if [ -n \"$_ids\" ]; then\n")
	fmt.Fprintf(&sb, "  aws events remove-targets --rule %s%s --ids $_ids\n", name, region)
	sb.WriteString("fi\n")
	fmt.Fprintf(&sb, "aws events delete-rule --name %s%s", name, region)
	return sb.String()
}

// shellQuote single-quotes s for safe inclusion in a bash command, escaping any
// embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// regionFlag returns " --region <r>" so the generated command targets the
// resource's own region, or "" when the region is unknown (the command then falls
// back to the caller's default region).
func regionFlag(region string) string {
	if region == "" {
		return ""
	}
	return " --region " + shellQuote(region)
}

// writeIfChanged writes data to path unless an identical file already exists,
// making re-runs idempotent (diff-before-write): a script that hasn't changed is
// left untouched.
func writeIfChanged(path string, data []byte) error {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return nil
	}
	// #nosec G306 -- remediation script must be executable; 0o700 keeps it owner-only
	return os.WriteFile(path, data, 0o700)
}
