package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stxkxs/matlock/internal/audit"
	"github.com/stxkxs/matlock/internal/cloud"
)

func TestWriteSARIF_StructureValid(t *testing.T) {
	var buf bytes.Buffer
	findings := []cloud.Finding{{
		Severity:  cloud.SeverityCritical,
		Type:      cloud.FindingAdminAccess,
		Provider:  "aws",
		Principal: &cloud.Principal{Name: "admin"},
		Detail:    "wildcard action",
	}}
	if err := WriteSARIF(&buf, findings, "v1.0.0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, buf.String())
	}
	if out["$schema"] == nil {
		t.Error("expected $schema in SARIF output")
	}
	if out["version"] != "2.1.0" {
		t.Errorf("SARIF version: got %v, want 2.1.0", out["version"])
	}
	runs, ok := out["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("expected at least one run")
	}
}

func TestWriteStorageSARIF(t *testing.T) {
	var buf bytes.Buffer
	findings := []cloud.BucketFinding{{
		Severity: cloud.SeverityCritical,
		Type:     cloud.BucketPublicAccess,
		Provider: "aws",
		Bucket:   "leaky",
		Region:   "us-east-1",
	}}
	if err := WriteStorageSARIF(&buf, findings, "v1.0.0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
}

func TestWriteSecretsSARIF(t *testing.T) {
	var buf bytes.Buffer
	findings := []cloud.SecretFinding{{
		Severity: cloud.SeverityHigh,
		Type:     "aws_key",
		Provider: "aws",
		Resource: "lambda:fn",
		Key:      "AWS_KEY",
		Detail:   "leaked",
	}}
	if err := WriteSecretsSARIF(&buf, findings, "v1.0.0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
}

func TestWriteAuditSARIF(t *testing.T) {
	var buf bytes.Buffer
	rep := &audit.Report{
		IAM:     []cloud.Finding{{Severity: cloud.SeverityCritical, Type: cloud.FindingAdminAccess, Provider: "aws", Principal: &cloud.Principal{Name: "x"}}},
		Storage: []cloud.BucketFinding{{Severity: cloud.SeverityHigh, Provider: "aws", Bucket: "b"}},
	}
	if err := WriteAuditSARIF(&buf, rep, "v1.0.0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("audit SARIF output is not valid JSON: %v", err)
	}
}

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		in   cloud.Severity
		want string
	}{
		{cloud.SeverityCritical, "error"},
		{cloud.SeverityHigh, "error"},
		{cloud.SeverityMedium, "warning"},
		{cloud.SeverityLow, "note"},
		{cloud.SeverityInfo, "note"},
		{"unknown", "note"},
	}
	for _, tt := range tests {
		got := sarifLevel(tt.in)
		if got != tt.want {
			t.Errorf("sarifLevel(%v): got %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBuildRules_NonEmpty(t *testing.T) {
	for name, builder := range map[string]func() []sarifRule{
		"iam":     buildRules,
		"storage": buildStorageRules,
		"secrets": buildSecretsRules,
		"network": buildNetworkRules,
	} {
		rules := builder()
		if len(rules) == 0 {
			t.Errorf("%s rules should not be empty", name)
		}
	}
}
