package compliance_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compliance"
	"github.com/nanohype/cloudgov/internal/output"
)

// The compliance loaders read reports a different package writes. Nothing binds
// the two struct definitions, so a renamed JSON tag on either side would leave
// the loader silently decoding zero values — every control mapped to that domain
// would then read NOT_EVALUATED on a report that is full of findings, and
// "cloudgov found nothing to evaluate" is indistinguishable from "the domain is
// clean". These round-trips are the binding: writer out, loader in, fields
// compared.

func writeReport(t *testing.T, name string, write func(*bytes.Buffer) error) string {
	t.Helper()
	var buf bytes.Buffer
	if err := write(&buf); err != nil {
		t.Fatalf("write %s report: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCertsReportRoundTrip(t *testing.T) {
	want := cloud.CertFinding{
		Severity: cloud.SeverityCritical, Status: cloud.CertExpired, Provider: "aws",
		Domain: "api.example.test", ARN: "arn:aws:acm:us-east-1:000000000000:certificate/abc",
		Region: "us-east-1", ExpiresAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		DaysLeft: -7, Detail: "expired 7 days ago",
	}
	path := writeReport(t, "certs.json", func(b *bytes.Buffer) error {
		return output.WriteCerts(b, []cloud.CertFinding{want}, nil)
	})

	got, err := compliance.LoadCertsReport(path)
	if err != nil {
		t.Fatalf("LoadCertsReport: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Status != want.Status || got[0].Domain != want.Domain || got[0].Severity != want.Severity {
		t.Errorf("round-trip lost fields:\n got %+v\nwant %+v", got[0], want)
	}
	// A1.2 keys on Status, so a Status that does not survive the round-trip
	// turns an expired certificate into a passing availability control.
	assertControlFails(t, compliance.InputFindings{Certs: got}, "A1.2")
}

func TestLoadTagsReportRoundTrip(t *testing.T) {
	want := cloud.TagFinding{
		Severity: cloud.SeverityMedium, Provider: "aws", ResourceType: "s3",
		ResourceID: "raw-data", Region: "us-east-1",
		MissingTags: []string{"Environment", "Team"},
	}
	path := writeReport(t, "tags.json", func(b *bytes.Buffer) error {
		return output.WriteTags(b, []cloud.TagFinding{want}, nil)
	})

	got, err := compliance.LoadTagsReport(path)
	if err != nil {
		t.Fatalf("LoadTagsReport: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].ResourceID != want.ResourceID || len(got[0].MissingTags) != len(want.MissingTags) {
		t.Errorf("round-trip lost fields:\n got %+v\nwant %+v", got[0], want)
	}
}

func TestLoadStorageReportRoundTrip(t *testing.T) {
	want := cloud.BucketFinding{
		Severity: cloud.SeverityCritical, Type: cloud.BucketPublicAccess, Provider: "aws",
		Bucket: "docs", Region: "us-east-1", Detail: "block public access disabled",
	}
	path := writeReport(t, "storage.json", func(b *bytes.Buffer) error {
		return output.WriteStorage(b, []cloud.BucketFinding{want}, nil)
	})

	got, err := compliance.LoadStorageReport(path)
	if err != nil {
		t.Fatalf("LoadStorageReport: %v", err)
	}
	if len(got) != 1 || got[0].Type != want.Type || got[0].Bucket != want.Bucket {
		t.Fatalf("round-trip lost fields: %+v", got)
	}
}

func TestLoadNetworkReportRoundTrip(t *testing.T) {
	want := cloud.NetworkFinding{
		Severity: cloud.SeverityHigh, Type: cloud.NetworkAdminPortOpen, Provider: "aws",
		Resource: "sg-1", Region: "us-east-1", Protocol: "tcp", Port: "22",
		CIDR: "0.0.0.0/0", Detail: "SSH open to the internet",
	}
	path := writeReport(t, "network.json", func(b *bytes.Buffer) error {
		return output.WriteNetwork(b, []cloud.NetworkFinding{want}, nil)
	})

	got, err := compliance.LoadNetworkReport(path)
	if err != nil {
		t.Fatalf("LoadNetworkReport: %v", err)
	}
	if len(got) != 1 || got[0].Type != want.Type || got[0].Resource != want.Resource {
		t.Fatalf("round-trip lost fields: %+v", got)
	}
}

func TestLoadIAMReportRoundTrip(t *testing.T) {
	want := cloud.Finding{
		Severity: cloud.SeverityCritical, Type: cloud.FindingAdminAccess, Provider: "aws",
		Resource: "role/admin", Detail: "AdministratorAccess attached",
	}
	path := writeReport(t, "iam.json", func(b *bytes.Buffer) error {
		return output.WriteIAM(b, []cloud.Finding{want}, 1, nil, nil)
	})

	got, err := compliance.LoadIAMReport(path)
	if err != nil {
		t.Fatalf("LoadIAMReport: %v", err)
	}
	if len(got) != 1 || got[0].Type != want.Type {
		t.Fatalf("round-trip lost fields: %+v", got)
	}
	assertControlFails(t, compliance.InputFindings{IAM: got}, "CC6.1")
}

// assertControlFails runs the whole SOC 2 benchmark over loaded findings and
// requires the named control to fail. Going through Evaluate rather than the
// control's evaluator is deliberate: it exercises the same path a `cloudgov
// compliance` run takes, so a break anywhere between the loader and the verdict
// shows up here.
func assertControlFails(t *testing.T, input compliance.InputFindings, controlID string) {
	t.Helper()
	report := compliance.Evaluate(compliance.GetBenchmark("soc2"), input)
	for _, r := range report.Results {
		if r.Control.ID != controlID {
			continue
		}
		if r.Status != compliance.StatusFail {
			t.Errorf("control %s = %s on loaded findings, want FAIL: %s", controlID, r.Status, r.Detail)
		}
		return
	}
	t.Errorf("control %s is not in the SOC 2 report", controlID)
}
