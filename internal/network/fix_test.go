package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stxkxs/matlock/internal/cloud"
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
			Provider: "gcp", Resource: "fw-1",
			Remediation: "gcloud compute firewall-rules delete fw-1",
		},
	}

	files, err := WriteFixScripts(findings, tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 scripts (aws + gcp), got %d: %v", len(files), files)
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

	// Verify gcp script content
	gcpBytes, _ := os.ReadFile(filepath.Join(tmp, "fix-network-gcp.sh"))
	gcp := string(gcpBytes)
	if !strings.Contains(gcp, "gcloud compute firewall-rules delete fw-1") {
		t.Errorf("gcp script missing remediation command")
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
