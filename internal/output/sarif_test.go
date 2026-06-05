package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compliance"
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
		"k8s":     buildK8sRules,
		"lambda":  buildLambdaRules,
		"drift":   buildDriftRules,
		"certs":   buildCertRules,
	} {
		rules := builder()
		if len(rules) == 0 {
			t.Errorf("%s rules should not be empty", name)
		}
	}
}

// decodeSARIF unmarshals a writer's output into the SARIF envelope, asserts the
// basic shape, and returns the single run's results.
func decodeSARIF(t *testing.T, b []byte) []sarifResult {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "cloudgov" {
		t.Errorf("driver name = %q, want cloudgov", log.Runs[0].Tool.Driver.Name)
	}
	return log.Runs[0].Results
}

func TestWriteK8sSARIF(t *testing.T) {
	findings := []cloud.K8sFinding{
		{Type: cloud.K8sClusterAdmin, Severity: cloud.SeverityCritical, Detail: "binds cluster-admin"},
		{Type: cloud.K8sDangerousVerb, Severity: cloud.SeverityMedium, Detail: "delete on *"},
	}
	var buf bytes.Buffer
	if err := WriteK8sSARIF(&buf, findings, "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	results := decodeSARIF(t, buf.Bytes())
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if results[0].Level != "error" {
		t.Errorf("CRITICAL -> level %q, want error", results[0].Level)
	}
	if results[1].Level != "warning" {
		t.Errorf("MEDIUM -> level %q, want warning", results[1].Level)
	}
}

func TestWriteLambdaSARIF(t *testing.T) {
	findings := []cloud.LambdaPolicyFinding{
		{Type: cloud.LambdaPublicInvoke, Severity: cloud.SeverityCritical, Detail: "public invoke"},
	}
	var buf bytes.Buffer
	if err := WriteLambdaSARIF(&buf, findings, "v1"); err != nil {
		t.Fatal(err)
	}
	results := decodeSARIF(t, buf.Bytes())
	if len(results) != 1 || results[0].RuleID != string(cloud.LambdaPublicInvoke) {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestWriteComplianceSARIF_OmitsPasses(t *testing.T) {
	report := compliance.ComplianceReport{
		Results: []compliance.ControlResult{
			{Control: compliance.Control{ID: "1.1", Title: "fail one", Severity: cloud.SeverityHigh}, Status: compliance.StatusFail, Detail: "failed"},
			{Control: compliance.Control{ID: "1.2", Title: "pass one", Severity: cloud.SeverityHigh}, Status: compliance.StatusPass},
			{Control: compliance.Control{ID: "1.3", Title: "n/a", Severity: cloud.SeverityLow}, Status: compliance.StatusNotEvaluated},
		},
	}
	var buf bytes.Buffer
	if err := WriteComplianceSARIF(&buf, report, "v1"); err != nil {
		t.Fatal(err)
	}
	results := decodeSARIF(t, buf.Bytes())
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2 (pass omitted)", len(results))
	}
	if results[0].Level != "error" {
		t.Errorf("HIGH fail -> level %q, want error", results[0].Level)
	}
	if results[1].Level != "note" {
		t.Errorf("not-evaluated -> level %q, want note", results[1].Level)
	}
}

func TestWriteDriftSARIF_OmitsInSync(t *testing.T) {
	results := []cloud.DriftResult{
		{Status: cloud.DriftModified, ResourceName: "aws_security_group.web", Detail: "ingress changed"},
		{Status: cloud.DriftDeleted, ResourceName: "aws_s3_bucket.logs", Detail: "missing"},
		{Status: cloud.DriftInSync, ResourceName: "aws_iam_role.app"},
	}
	var buf bytes.Buffer
	if err := WriteDriftSARIF(&buf, results, "v1"); err != nil {
		t.Fatal(err)
	}
	got := decodeSARIF(t, buf.Bytes())
	if len(got) != 2 {
		t.Fatalf("results = %d, want 2 (in-sync omitted)", len(got))
	}
	if got[0].Level != "warning" {
		t.Errorf("MODIFIED -> level %q, want warning", got[0].Level)
	}
	if got[1].Level != "error" {
		t.Errorf("DELETED -> level %q, want error", got[1].Level)
	}
}

func TestWriteCertsSARIF(t *testing.T) {
	findings := []cloud.CertFinding{
		{Severity: cloud.SeverityCritical, Status: cloud.CertExpired, Provider: "aws", Domain: "gone.example.com", Detail: "expired 5 days ago"},
		{Severity: cloud.SeverityLow, Status: cloud.CertLow, Provider: "aws", Domain: "ok.example.com", Detail: "expires in 80 days"},
	}
	var buf bytes.Buffer
	if err := WriteCertsSARIF(&buf, findings, "v1"); err != nil {
		t.Fatal(err)
	}
	got := decodeSARIF(t, buf.Bytes())
	if len(got) != 2 {
		t.Fatalf("results = %d, want 2", len(got))
	}
	if got[0].RuleID != string(cloud.CertExpired) || got[0].Level != "error" {
		t.Errorf("expired: ruleID=%q level=%q, want %s/error", got[0].RuleID, got[0].Level, cloud.CertExpired)
	}
	if got[1].Level != "note" {
		t.Errorf("low-severity cert -> level %q, want note", got[1].Level)
	}

	// Also assert the driver rules table levels (defaultConfiguration.level is what
	// GitHub Advanced Security reads for rule defaults), not just per-result levels.
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	ruleLevel := make(map[string]string)
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		ruleLevel[r.ID] = r.DefaultConfig.Level
	}
	for status, want := range map[cloud.CertStatus]string{
		cloud.CertExpired: "error",
		cloud.CertMedium:  "warning",
		cloud.CertLow:     "note",
	} {
		if got := ruleLevel[string(status)]; got != want {
			t.Errorf("rule %s defaultConfiguration.level = %q, want %q", status, got, want)
		}
	}
}
