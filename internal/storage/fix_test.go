package storage

import (
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
			Provider: "gcp", Bucket: "gcs-bucket",
			Remediation: "gcloud storage buckets update gs://gcs-bucket --versioning",
		},
	}

	files, err := WriteFixScripts(findings, tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 scripts (aws + gcp), got %d: %v", len(files), files)
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

	gcpBytes, _ := os.ReadFile(filepath.Join(tmp, "fix-gcp.sh"))
	gcp := string(gcpBytes)
	if !strings.Contains(gcp, "gcloud storage buckets update gs://gcs-bucket --versioning") {
		t.Errorf("gcp script missing remediation command")
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
