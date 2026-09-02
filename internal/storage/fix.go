package storage

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/fix"
)

// WriteFixScripts generates one shell remediation script per provider and writes them
// to outDir. Scripts are named fix-<provider>.sh. Returns the list of files written.
func WriteFixScripts(findings []cloud.BucketFinding, outDir string) ([]string, error) {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
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
		name, err := fix.PathUnder(outDir, fmt.Sprintf("fix-%s.sh", provider))
		if err != nil {
			return written, err //coverage:ignore unreachable while the check above stands
		}
		if err := writeProviderScript(name, provider, byProvider[provider]); err != nil {
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
	sb.WriteString("# cloudgov storage audit --fix\n")
	fmt.Fprintf(&sb, "# Provider: %s\n", provider)
	fmt.Fprintf(&sb, "# Findings: %d\n", len(findings))
	sb.WriteString("\n")

	for _, f := range findings {
		fmt.Fprintf(&sb, "# [%s] %s — %s", f.Severity, f.Type, f.Bucket)
		if f.Region != "" {
			fmt.Fprintf(&sb, " (%s)", f.Region)
		}
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "# %s\n", f.Detail)
		sb.WriteString(f.Remediation)
		sb.WriteString("\n\n")
	}

	// #nosec G306 -- remediation script must be executable; 0o700 keeps it owner-only
	if err := os.WriteFile(path, []byte(sb.String()), 0o700); err != nil {
		return err
	}
	return nil
}
