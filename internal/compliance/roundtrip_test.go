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

	got, _, err := compliance.LoadCertsReport(path)
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

	got, _, err := compliance.LoadTagsReport(path)
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

	got, _, err := compliance.LoadStorageReport(path)
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

	got, _, err := compliance.LoadNetworkReport(path)
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
		return output.WriteIAM(b, []cloud.Finding{want}, 1, 1, nil, nil, cloud.ScanWindow{RequestedDays: 90, ObservedDays: 90})
	})

	got, _, err := compliance.LoadIAMReport(path)
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

// Every loader returns the report's unread record alongside its findings, and a
// call site that discards it with `_` costs nothing that statement coverage can
// see: replacing all five returns with `report.Findings, nil, nil` leaves this
// package's statement coverage untouched, while a benchmark evaluated over a scan
// denied half an account renders exactly like one evaluated over the whole of it.
// That mutation fails here.
//
// The record is the second return because it is not a finding: findings are
// severity-filtered and this has to survive every filter. So it is asserted
// here, per loader, in both directions — carried when the report has one, and
// empty when it does not.
func TestEveryLoaderCarriesTheReportsUnreadRecord(t *testing.T) {
	const unread = "describe regions: AccessDenied; scanned us-east-1 only"

	loaders := map[string]struct {
		write func(*bytes.Buffer, []string) error
		load  func(string) ([]string, error)
	}{
		"iam": {
			write: func(b *bytes.Buffer, inc []string) error {
				return output.WriteIAM(b, []cloud.Finding{{Severity: cloud.SeverityHigh, Type: cloud.FindingAdminAccess, Provider: "aws"}}, 1, 1, nil, inc, cloud.ScanWindow{RequestedDays: 90, ObservedDays: 90})
			},
			load: func(p string) ([]string, error) { _, inc, err := compliance.LoadIAMReport(p); return inc, err },
		},
		"storage": {
			write: func(b *bytes.Buffer, inc []string) error {
				return output.WriteStorage(b, []cloud.BucketFinding{{Severity: cloud.SeverityHigh, Type: cloud.BucketUnencrypted, Provider: "aws", Bucket: "b"}}, inc)
			},
			load: func(p string) ([]string, error) { _, inc, err := compliance.LoadStorageReport(p); return inc, err },
		},
		"network": {
			write: func(b *bytes.Buffer, inc []string) error {
				return output.WriteNetwork(b, []cloud.NetworkFinding{{Severity: cloud.SeverityHigh, Type: cloud.NetworkAdminPortOpen, Provider: "aws", Resource: "sg-1"}}, inc)
			},
			load: func(p string) ([]string, error) { _, inc, err := compliance.LoadNetworkReport(p); return inc, err },
		},
		"certs": {
			write: func(b *bytes.Buffer, inc []string) error {
				return output.WriteCerts(b, []cloud.CertFinding{{Severity: cloud.SeverityHigh, Provider: "aws", Domain: "example.test", ExpiresAt: time.Now()}}, inc)
			},
			load: func(p string) ([]string, error) { _, inc, err := compliance.LoadCertsReport(p); return inc, err },
		},
		"tags": {
			write: func(b *bytes.Buffer, inc []string) error {
				return output.WriteTags(b, []cloud.TagFinding{{Severity: cloud.SeverityMedium, Provider: "aws", ResourceID: "r", MissingTags: []string{"Environment"}}}, inc)
			},
			load: func(p string) ([]string, error) { _, inc, err := compliance.LoadTagsReport(p); return inc, err },
		},
	}

	for domain, l := range loaders {
		t.Run(domain+"/carries an unread record", func(t *testing.T) {
			path := writeReport(t, domain+".json", func(b *bytes.Buffer) error { return l.write(b, []string{unread}) })
			got, err := l.load(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(got) != 1 || got[0] != unread {
				t.Errorf("the %s loader dropped the report's unread record: got %v, want [%q]", domain, got, unread)
			}
		})

		t.Run(domain+"/reports a whole scan as whole", func(t *testing.T) {
			// The positive control on the assertion above: a loader returning a
			// constant non-empty record would pass it and fail here.
			path := writeReport(t, domain+"-clean.json", func(b *bytes.Buffer) error { return l.write(b, nil) })
			got, err := l.load(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("the %s loader invented an unread record for a whole scan: %v", domain, got)
			}
		})
	}
}
