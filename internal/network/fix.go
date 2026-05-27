package network

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stxkxs/matlock/internal/cloud"
)

// WriteFixScripts generates one shell remediation script per provider and
// writes them to outDir. Scripts are named fix-network-<provider>.sh.
// Returns the list of files written. Findings without a Remediation string
// are skipped — there's nothing to script.
func WriteFixScripts(findings []cloud.NetworkFinding, outDir string) ([]string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	byProvider := make(map[string][]cloud.NetworkFinding)
	for _, f := range findings {
		if f.Remediation == "" {
			continue
		}
		byProvider[f.Provider] = append(byProvider[f.Provider], f)
	}

	var written []string
	for provider, pfindings := range byProvider {
		name := filepath.Join(outDir, fmt.Sprintf("fix-network-%s.sh", provider))
		if err := writeNetworkScript(name, provider, pfindings); err != nil {
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
	sb.WriteString("# matlock network audit --fix\n")
	sb.WriteString(fmt.Sprintf("# Provider: %s\n", provider))
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("# Findings: %d\n", len(findings)))
	sb.WriteString("#\n")
	sb.WriteString("# Review each command before running. These revoke security-group / firewall /\n")
	sb.WriteString("# NSG rules — running them blindly may cut off legitimate traffic.\n")
	sb.WriteString("\n")

	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("# [%s] %s — %s", f.Severity, f.Type, f.Resource))
		if f.Region != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", f.Region))
		}
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("# proto=%s port=%s cidr=%s\n", f.Protocol, f.Port, f.CIDR))
		if f.Detail != "" {
			sb.WriteString(fmt.Sprintf("# %s\n", f.Detail))
		}
		sb.WriteString(f.Remediation)
		sb.WriteString("\n\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0o755)
}
