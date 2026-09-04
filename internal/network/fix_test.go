package network

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestWriteFixScripts_GroupsByProvider(t *testing.T) {
	tmp := t.TempDir()
	findings := []cloud.NetworkFinding{
		{
			Severity: cloud.SeverityCritical, Type: cloud.NetworkAdminPortOpen,
			Provider: "aws", Resource: "sg-1", Region: "us-east-1",
			Protocol: "tcp", Port: "22", CIDR: "0.0.0.0/0",
			Detail:      "SSH open to internet",
			Remediation: "aws ec2 revoke-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0",
		},
		{
			Severity: cloud.SeverityHigh, Type: cloud.NetworkOpenIngress,
			Provider: "aws", Resource: "sg-2",
			Remediation: "aws ec2 revoke-security-group-ingress --group-id sg-2 ...",
		},
		{
			Severity: cloud.SeverityCritical, Type: cloud.NetworkAdminPortOpen,
			Provider: "gamma", Resource: "fw-1",
			Remediation: "fakectl firewall-rules delete fw-1",
		},
	}

	files, err := WriteFixScripts(findings, tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 scripts (aws + gamma), got %d: %v", len(files), files)
	}

	// Verify aws script content
	awsBytes, err := os.ReadFile(filepath.Join(tmp, "fix-network-aws.sh"))
	if err != nil {
		t.Fatalf("read aws script: %v", err)
	}
	aws := string(awsBytes)
	for _, want := range []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"# Provider: aws",
		"# Findings: 2",
		"sg-1",
		"sg-2",
		"revoke-security-group-ingress",
	} {
		if !strings.Contains(aws, want) {
			t.Errorf("aws script missing %q", want)
		}
	}

	// Verify gamma script content
	gammaBytes, _ := os.ReadFile(filepath.Join(tmp, "fix-network-gamma.sh"))
	gamma := string(gammaBytes)
	if !strings.Contains(gamma, "fakectl firewall-rules delete fw-1") {
		t.Errorf("gamma script missing remediation command")
	}
}

func TestWriteFixScripts_SkipsFindingsWithoutRemediation(t *testing.T) {
	tmp := t.TempDir()
	findings := []cloud.NetworkFinding{
		{Provider: "aws", Resource: "sg-1"}, // no Remediation
	}
	files, err := WriteFixScripts(findings, tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected no scripts for findings without remediation, got %v", files)
	}
}

func TestWriteFixScripts_ScriptIsExecutable(t *testing.T) {
	tmp := t.TempDir()
	findings := []cloud.NetworkFinding{
		{Provider: "aws", Resource: "sg-1", Remediation: "echo fix"},
	}
	files, err := WriteFixScripts(findings, tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// 0o755 — owner-executable bit must be set
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("script not executable: mode %v", info.Mode().Perm())
	}
}

func TestWriteFixScripts_CreatesOutDir(t *testing.T) {
	tmp := t.TempDir()
	nested := filepath.Join(tmp, "fixes", "subdir")
	findings := []cloud.NetworkFinding{
		{Provider: "aws", Resource: "sg-1", Remediation: "x"},
	}
	_, err := WriteFixScripts(findings, nested)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Errorf("nested outDir should be created: %v", err)
	}
}

// The provider on a saved finding decides a filename, and `cloudgov remediate`
// reads it out of a report an operator received rather than one cloudgov wrote.
// Written 0700 with contents the same report supplies, an escaping name is an
// attacker-chosen executable at an attacker-chosen path.
func TestWriteFixScriptsRefusesAProviderThatNamesAPath(t *testing.T) {
	for _, provider := range []string{
		"../ESCAPED",
		"../../ESCAPED",
		"../../../ESCAPED",
		"sub/ESCAPED",
		// Segments that cancel back inside are refused too: the result is a file
		// this code did not name, whether or not it lands where it meant to.
		"x/../aws",
		"/etc/cron.d/ESCAPED",
		"..",
		"",
	} {
		t.Run(provider, func(t *testing.T) {
			root := t.TempDir()
			out := filepath.Join(root, "out")

			_, err := WriteFixScripts([]cloud.NetworkFinding{{
				Severity: cloud.SeverityCritical, Type: cloud.NetworkAdminPortOpen,
				Provider: provider, Resource: "sg-1",
				Remediation: "echo attacker-chosen-command",
			}}, out)
			if err == nil {
				t.Fatalf("provider %q was accepted; it names a path, not a file", provider)
			}

			// The refusal is only worth having if nothing was written. Checked over
			// the whole temporary tree rather than over `out`, because the failure
			// this guards against is a file appearing somewhere else.
			for _, path := range treeFiles(t, root) {
				if filepath.Dir(path) != out {
					t.Errorf("provider %q produced %s, outside %s", provider, path, out)
				}
			}
		})
	}
}

// treeFiles returns every regular file under root.
func treeFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}
