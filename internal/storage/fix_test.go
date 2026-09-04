package storage

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
	findings := []cloud.BucketFinding{
		{
			Severity: cloud.SeverityCritical, Type: cloud.BucketPublicACL,
			Provider: "aws", Bucket: "public-bucket", Region: "us-east-1",
			Detail:      "Bucket ACL grants public read",
			Remediation: "aws s3api put-public-access-block --bucket public-bucket --public-access-block-configuration BlockPublicAcls=true",
		},
		{
			Severity: cloud.SeverityHigh, Type: cloud.BucketUnencrypted,
			Provider: "aws", Bucket: "plain-bucket",
			Remediation: "aws s3api put-bucket-encryption --bucket plain-bucket ...",
		},
		{
			Severity: cloud.SeverityHigh, Type: cloud.BucketNoVersioning,
			Provider: "gamma", Bucket: "gamma-bucket",
			Remediation: "fakectl buckets update gamma-bucket --enable-versioning",
		},
	}

	files, err := WriteFixScripts(findings, tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 scripts (aws + gamma), got %d: %v", len(files), files)
	}

	awsBytes, err := os.ReadFile(filepath.Join(tmp, "fix-aws.sh"))
	if err != nil {
		t.Fatalf("read aws script: %v", err)
	}
	aws := string(awsBytes)
	for _, want := range []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"# Provider: aws",
		"# Findings: 2",
		"public-bucket",
		"plain-bucket",
		"put-public-access-block",
	} {
		if !strings.Contains(aws, want) {
			t.Errorf("aws script missing %q", want)
		}
	}

	gammaBytes, _ := os.ReadFile(filepath.Join(tmp, "fix-gamma.sh"))
	gamma := string(gammaBytes)
	if !strings.Contains(gamma, "fakectl buckets update gamma-bucket --enable-versioning") {
		t.Errorf("gamma script missing remediation command")
	}
}

func TestWriteFixScripts_SkipsFindingsWithoutRemediation(t *testing.T) {
	tmp := t.TempDir()
	findings := []cloud.BucketFinding{
		{Provider: "aws", Bucket: "b1"}, // no Remediation
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
	findings := []cloud.BucketFinding{
		{Provider: "aws", Bucket: "b1", Remediation: "echo fix"},
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
	findings := []cloud.BucketFinding{
		{Provider: "aws", Bucket: "b1", Remediation: "x"},
	}
	_, err := WriteFixScripts(findings, nested)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Errorf("nested outDir should be created: %v", err)
	}
}

// The generated script must be byte-stable for the same findings so it diffs
// cleanly when committed — no wall-clock timestamp or other run-varying content.
func TestWriteFixScripts_Deterministic(t *testing.T) {
	findings := []cloud.BucketFinding{
		{
			Severity: cloud.SeverityHigh, Type: cloud.BucketUnencrypted,
			Provider: "aws", Bucket: "b1",
			Detail:      "no default encryption",
			Remediation: "aws s3api put-bucket-encryption --bucket b1 ...",
		},
	}

	read := func() string {
		dir := t.TempDir()
		if _, err := WriteFixScripts(findings, dir); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "fix-aws.sh"))
		if err != nil {
			t.Fatalf("read script: %v", err)
		}
		return string(b)
	}

	if first, second := read(), read(); first != second {
		t.Errorf("non-deterministic script output:\nfirst:\n%s\nsecond:\n%s", first, second)
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

			_, err := WriteFixScripts([]cloud.BucketFinding{{
				Severity: cloud.SeverityCritical, Type: cloud.BucketPublicACL,
				Provider: provider, Bucket: "b",
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
