package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// WriteFixScripts generates one shell remediation script per provider and writes them
// to outDir. Scripts are named fix-<provider>.sh. Returns the list of files written.
func WriteFixScripts(findings []cloud.BucketFinding, outDir string) ([]string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	// Group findings by provider.
	byProvider := make(map[string][]cloud.BucketFinding)
	for _, f := range findings {
		if f.Remediation == "" {
			continue
		}
		byProvider[f.Provider] = append(byProvider[f.Provider], f)
	}

	var written []string
	for provider, pfindings := range byProvider {
		name := filepath.Join(outDir, fmt.Sprintf("fix-%s.sh", provider))
		if err := writeProviderScript(name, provider, pfindings); err != nil {
			return written, fmt.Errorf("write %s: %w", name, err)
		}
		written = append(written, name)
	}
	return written, nil
}

func writeProviderScript(path, provider string, findings []cloud.BucketFinding) error {
	var sb strings.Builder

	sb.WriteString("#!/usr/bin/env bash\n")
	sb.WriteString("set -euo pipefail\n")
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("# cloudgov storage audit --fix\n"))
	sb.WriteString(fmt.Sprintf("# Provider: %s\n", provider))
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("# Findings: %d\n", len(findings)))
	sb.WriteString("\n")

	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("# [%s] %s — %s", f.Severity, f.Type, f.Bucket))
		if f.Region != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", f.Region))
		}
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("# %s\n", f.Detail))
		sb.WriteString(f.Remediation)
		sb.WriteString("\n\n")
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0o755); err != nil {
		return err
	}
	return nil
}
