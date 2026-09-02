package network

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/fix"
)

// WriteFixScripts generates one shell remediation script per provider and
// writes them to outDir. Scripts are named fix-network-<provider>.sh.
// Returns the list of files written. Findings without a Remediation string
// are skipped — there's nothing to script.
func WriteFixScripts(findings []cloud.NetworkFinding, outDir string) ([]string, error) {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	byProvider := make(map[string][]cloud.NetworkFinding)
	for _, f := range findings {
		if f.Remediation == "" {
			continue
		}
		byProvider[f.Provider] = append(byProvider[f.Provider], f)
	}

	// Sorted rather than ranged over the map: the provider decides a filename, so
	// map order decides which refusal an operator sees and in what order the
	// written files are reported. Neither should differ between two runs over the
	// same report.
	providers := make([]string, 0, len(byProvider))
	for provider := range byProvider {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	var written []string
	for _, provider := range providers {
		if err := fix.NameComponent("provider", provider); err != nil {
			return written, err
		}
		// NameComponent has already refused every provider that could trip this:
		// no separator, no bare "..", and the prefix below leaves nothing for
		// PathUnder to reject. Kept because containment must not rest on the
		// order of two statements — this is the layer that holds if the check
		// above is moved, weakened, or forgotten by the next generator.
		name, err := fix.PathUnder(outDir, fmt.Sprintf("fix-network-%s.sh", provider))
		if err != nil {
			return written, err //coverage:ignore unreachable while the check above stands
		}
		if err := writeNetworkScript(name, provider, byProvider[provider]); err != nil {
			return written, fmt.Errorf("write %s: %w", name, err)
		}
		written = append(written, name)
	}
	return written, nil
}

func writeNetworkScript(path, provider string, findings []cloud.NetworkFinding) error {
	var sb strings.Builder

	sb.WriteString("#!/usr/bin/env bash\n")
	sb.WriteString("set -euo pipefail\n")
	sb.WriteString("\n")
	sb.WriteString("# cloudgov network audit --fix\n")
	fmt.Fprintf(&sb, "# Provider: %s\n", fix.CommentText(provider))
	fmt.Fprintf(&sb, "# Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&sb, "# Findings: %d\n", len(findings))
	sb.WriteString("#\n")
	sb.WriteString("# Review each command before running. These revoke security-group / firewall /\n")
	sb.WriteString("# NSG rules — running them blindly may cut off legitimate traffic.\n")
	sb.WriteString("\n")

	for _, f := range findings {
		fmt.Fprintf(&sb, "# [%s] %s — %s", fix.CommentText(string(f.Severity)), fix.CommentText(string(f.Type)), fix.CommentText(f.Resource))
		if f.Region != "" {
			fmt.Fprintf(&sb, " (%s)", fix.CommentText(f.Region))
		}
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "# proto=%s port=%s cidr=%s\n", fix.CommentText(f.Protocol), fix.CommentText(f.Port), fix.CommentText(f.CIDR))
		if f.Detail != "" {
			fmt.Fprintf(&sb, "# %s\n", fix.CommentText(f.Detail))
		}
		sb.WriteString(f.Remediation)
		sb.WriteString("\n\n")
	}

	// #nosec G306 -- remediation script must be executable; 0o700 keeps it owner-only
	return os.WriteFile(path, []byte(sb.String()), 0o700)
}
