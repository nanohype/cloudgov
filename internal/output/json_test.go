package output

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compliance"
)

// roundTrip encodes via fn into a buffer, then decodes into T.
func roundTrip[T any](t *testing.T, fn func(*bytes.Buffer) error) T {
	t.Helper()
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		t.Fatalf("write error: %v", err)
	}
	var out T
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal error: %v (json: %s)", err, buf.String())
	}
	return out
}

func TestWriteIAM(t *testing.T) {
	findings := []cloud.Finding{
		{
			Severity:    cloud.SeverityCritical,
			Type:        cloud.FindingAdminAccess,
			Provider:    "aws",
			Principal:   &cloud.Principal{ID: "p1", Name: "admin-role", Type: cloud.PrincipalRole, Provider: "aws"},
			Resource:    "arn:aws:iam:::role/admin-role",
			Detail:      "has admin access",
			Remediation: "restrict permissions",
		},
		{
			Severity:    cloud.SeverityHigh,
			Type:        cloud.FindingUnusedPermission,
			Provider:    "aws",
			Principal:   &cloud.Principal{ID: "p2", Name: "dev-user", Type: cloud.PrincipalUser, Provider: "aws"},
			Resource:    "arn:aws:s3:::*",
			Detail:      "permission never used",
			Remediation: "remove unused permission",
		},
		{
			Severity:  cloud.SeverityLow,
			Type:      cloud.FindingWildcardResource,
			Provider:  "gamma",
			Principal: nil,
			Resource:  "*",
			Detail:    "wildcard resource",
		},
	}

	type iamOut struct {
		Findings   []json.RawMessage `json:"findings"`
		Total      int               `json:"total"`
		Principals int               `json:"principals_scanned"`
	}

	out := roundTrip[iamOut](t, func(buf *bytes.Buffer) error {
		return WriteIAM(buf, findings, 5, 5, nil, nil)
	})

	if out.Total != len(findings) {
		t.Errorf("total: got %d, want %d", out.Total, len(findings))
	}
	if out.Principals != 5 {
		t.Errorf("principals_scanned: got %d, want 5", out.Principals)
	}
	if len(out.Findings) != len(findings) {
		t.Errorf("findings length: got %d, want %d", len(out.Findings), len(findings))
	}

	tests := []struct {
		idx      int
		severity string
		typ      string
		provider string
	}{
		{0, "CRITICAL", "ADMIN_ACCESS", "aws"},
		{1, "HIGH", "UNUSED_PERMISSION", "aws"},
		{2, "LOW", "WILDCARD_RESOURCE", "gamma"},
	}
	for _, tc := range tests {
		var f map[string]interface{}
		if err := json.Unmarshal(out.Findings[tc.idx], &f); err != nil {
			t.Fatalf("finding[%d] unmarshal: %v", tc.idx, err)
		}
		if got := f["Severity"]; got != tc.severity {
			t.Errorf("finding[%d].Severity: got %v, want %s", tc.idx, got, tc.severity)
		}
		if got := f["Type"]; got != tc.typ {
			t.Errorf("finding[%d].Type: got %v, want %s", tc.idx, got, tc.typ)
		}
		if got := f["Provider"]; got != tc.provider {
			t.Errorf("finding[%d].Provider: got %v, want %s", tc.idx, got, tc.provider)
		}
	}
}

func TestWriteIAMEmpty(t *testing.T) {
	type iamOut struct {
		Findings   []json.RawMessage `json:"findings"`
		Total      int               `json:"total"`
		Principals int               `json:"principals_scanned"`
	}
	out := roundTrip[iamOut](t, func(buf *bytes.Buffer) error {
		return WriteIAM(buf, nil, 0, 0, nil, nil)
	})
	if out.Total != 0 {
		t.Errorf("total: got %d, want 0", out.Total)
	}
	if out.Principals != 0 {
		t.Errorf("principals_scanned: got %d, want 0", out.Principals)
	}
}

func TestWriteIAMPrincipalNil(t *testing.T) {
	findings := []cloud.Finding{
		{Severity: cloud.SeverityInfo, Type: cloud.FindingBroadScope, Provider: "beta", Principal: nil, Resource: "/accounts/*"},
	}
	type iamOut struct {
		Findings []json.RawMessage `json:"findings"`
		Total    int               `json:"total"`
	}
	out := roundTrip[iamOut](t, func(buf *bytes.Buffer) error {
		return WriteIAM(buf, findings, 1, 1, nil, nil)
	})
	if out.Total != 1 {
		t.Errorf("total: got %d, want 1", out.Total)
	}
	var f map[string]interface{}
	if err := json.Unmarshal(out.Findings[0], &f); err != nil {
		t.Fatalf("unmarshal finding: %v", err)
	}
	if principal, ok := f["Principal"]; ok && principal != nil {
		t.Errorf("Principal should be nil, got %v", principal)
	}
}

func TestWriteStorage(t *testing.T) {
	findings := []cloud.BucketFinding{
		{
			Severity:    cloud.SeverityCritical,
			Type:        cloud.BucketPublicAccess,
			Provider:    "aws",
			Bucket:      "my-public-bucket",
			Region:      "us-east-1",
			Detail:      "bucket is publicly accessible",
			Remediation: "enable block public access",
		},
		{
			Severity: cloud.SeverityHigh,
			Type:     cloud.BucketUnencrypted,
			Provider: "gamma",
			Bucket:   "unencrypted-data",
			Region:   "region-1",
			Detail:   "bucket has no encryption",
		},
		{
			Severity: cloud.SeverityMedium,
			Type:     cloud.BucketNoVersioning,
			Provider: "beta",
			Bucket:   "no-version-container",
			Region:   "region-2",
		},
	}

	type storageOut struct {
		Findings []json.RawMessage `json:"findings"`
		Total    int               `json:"total"`
	}

	out := roundTrip[storageOut](t, func(buf *bytes.Buffer) error {
		return WriteStorage(buf, findings, nil)
	})

	if out.Total != len(findings) {
		t.Errorf("total: got %d, want %d", out.Total, len(findings))
	}
	if len(out.Findings) != len(findings) {
		t.Errorf("findings length: got %d, want %d", len(out.Findings), len(findings))
	}

	tests := []struct {
		idx    int
		bucket string
		typ    string
	}{
		{0, "my-public-bucket", "PUBLIC_ACCESS"},
		{1, "unencrypted-data", "UNENCRYPTED"},
		{2, "no-version-container", "NO_VERSIONING"},
	}
	for _, tc := range tests {
		var f map[string]interface{}
		if err := json.Unmarshal(out.Findings[tc.idx], &f); err != nil {
			t.Fatalf("finding[%d] unmarshal: %v", tc.idx, err)
		}
		if got := f["Bucket"]; got != tc.bucket {
			t.Errorf("finding[%d].Bucket: got %v, want %s", tc.idx, got, tc.bucket)
		}
		if got := f["Type"]; got != tc.typ {
			t.Errorf("finding[%d].Type: got %v, want %s", tc.idx, got, tc.typ)
		}
	}
}

func TestWriteStorageEmpty(t *testing.T) {
	type storageOut struct {
		Findings []json.RawMessage `json:"findings"`
		Total    int               `json:"total"`
	}
	out := roundTrip[storageOut](t, func(buf *bytes.Buffer) error {
		return WriteStorage(buf, nil, nil)
	})
	if out.Total != 0 {
		t.Errorf("total: got %d, want 0", out.Total)
	}
}

func TestWriteOrphans(t *testing.T) {
	orphans := []cloud.OrphanResource{
		{Kind: cloud.OrphanDisk, ID: "vol-abc", Name: "old-disk", Region: "us-east-1", Provider: "aws", MonthlyCost: 12.50, Detail: "unattached"},
		{Kind: cloud.OrphanIP, ID: "eip-xyz", Name: "unused-eip", Region: "us-west-2", Provider: "aws", MonthlyCost: 3.60},
		{Kind: cloud.OrphanLoadBalancer, ID: "lb-123", Name: "stale-lb", Region: "eu-west-1", Provider: "aws", MonthlyCost: 20.00},
	}

	type resourceItem struct {
		Kind        string  `json:"Kind"`
		ID          string  `json:"ID"`
		MonthlyCost float64 `json:"MonthlyCost"`
	}
	type orphansOut struct {
		Resources           []resourceItem `json:"resources"`
		Total               int            `json:"total"`
		EstimatedMonthlyUSD float64        `json:"estimated_monthly_usd"`
	}

	out := roundTrip[orphansOut](t, func(buf *bytes.Buffer) error {
		return WriteOrphans(buf, orphans, nil)
	})

	if out.Total != len(orphans) {
		t.Errorf("total: got %d, want %d", out.Total, len(orphans))
	}

	wantCost := 12.50 + 3.60 + 20.00
	if out.EstimatedMonthlyUSD != wantCost {
		t.Errorf("estimated_monthly_usd: got %f, want %f", out.EstimatedMonthlyUSD, wantCost)
	}

	if len(out.Resources) != len(orphans) {
		t.Errorf("resources length: got %d, want %d", len(out.Resources), len(orphans))
	}

	if out.Resources[0].Kind != "disk" {
		t.Errorf("resources[0].Kind: got %s, want disk", out.Resources[0].Kind)
	}
	if out.Resources[1].Kind != "ip" {
		t.Errorf("resources[1].Kind: got %s, want ip", out.Resources[1].Kind)
	}
	if out.Resources[2].Kind != "load_balancer" {
		t.Errorf("resources[2].Kind: got %s, want load_balancer", out.Resources[2].Kind)
	}
}

func TestWriteOrphansEmpty(t *testing.T) {
	type orphansOut struct {
		Resources           []json.RawMessage `json:"resources"`
		Total               int               `json:"total"`
		EstimatedMonthlyUSD float64           `json:"estimated_monthly_usd"`
	}
	out := roundTrip[orphansOut](t, func(buf *bytes.Buffer) error {
		return WriteOrphans(buf, nil, nil)
	})
	if out.Total != 0 {
		t.Errorf("total: got %d, want 0", out.Total)
	}
	if out.EstimatedMonthlyUSD != 0 {
		t.Errorf("estimated_monthly_usd: got %f, want 0", out.EstimatedMonthlyUSD)
	}
}

func TestWriteOrphansMonthlyCostSum(t *testing.T) {
	orphans := []cloud.OrphanResource{
		{Kind: cloud.OrphanSnapshot, ID: "snap-1", MonthlyCost: 0},
		{Kind: cloud.OrphanImage, ID: "ami-1", MonthlyCost: 0},
	}
	type orphansOut struct {
		EstimatedMonthlyUSD float64 `json:"estimated_monthly_usd"`
		Total               int     `json:"total"`
	}
	out := roundTrip[orphansOut](t, func(buf *bytes.Buffer) error {
		return WriteOrphans(buf, orphans, nil)
	})
	if out.EstimatedMonthlyUSD != 0 {
		t.Errorf("estimated_monthly_usd: got %f, want 0", out.EstimatedMonthlyUSD)
	}
	if out.Total != 2 {
		t.Errorf("total: got %d, want 2", out.Total)
	}
}

func TestWriteCost(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	diffs := []cloud.CostDiff{
		{
			Provider:    "aws",
			BeforeStart: now,
			BeforeEnd:   now.AddDate(0, 1, 0),
			AfterStart:  now.AddDate(0, 1, 0),
			AfterEnd:    now.AddDate(0, 2, 0),
			Entries: []cloud.CostDiffEntry{
				{Service: "EC2", Before: 100.0, After: 120.0, Delta: 20.0, PctChange: 20.0},
				{Service: "S3", Before: 50.0, After: 45.0, Delta: -5.0, PctChange: -10.0},
			},
			TotalBefore: 150.0,
			TotalAfter:  165.0,
			TotalDelta:  15.0,
		},
	}

	type entryItem struct {
		Service   string  `json:"Service"`
		Before    float64 `json:"Before"`
		After     float64 `json:"After"`
		Delta     float64 `json:"Delta"`
		PctChange float64 `json:"PctChange"`
	}
	type diffItem struct {
		Provider    string      `json:"Provider"`
		Entries     []entryItem `json:"Entries"`
		TotalBefore float64     `json:"TotalBefore"`
		TotalAfter  float64     `json:"TotalAfter"`
		TotalDelta  float64     `json:"TotalDelta"`
	}
	type costOut struct {
		Diffs []diffItem `json:"diffs"`
	}

	out := roundTrip[costOut](t, func(buf *bytes.Buffer) error {
		return WriteCost(buf, diffs, nil)
	})

	if len(out.Diffs) != 1 {
		t.Fatalf("diffs length: got %d, want 1", len(out.Diffs))
	}

	d := out.Diffs[0]
	if d.Provider != "aws" {
		t.Errorf("Provider: got %s, want aws", d.Provider)
	}
	if d.TotalBefore != 150.0 {
		t.Errorf("TotalBefore: got %f, want 150.0", d.TotalBefore)
	}
	if d.TotalAfter != 165.0 {
		t.Errorf("TotalAfter: got %f, want 165.0", d.TotalAfter)
	}
	if d.TotalDelta != 15.0 {
		t.Errorf("TotalDelta: got %f, want 15.0", d.TotalDelta)
	}
	if len(d.Entries) != 2 {
		t.Fatalf("entries length: got %d, want 2", len(d.Entries))
	}
	if d.Entries[0].Service != "EC2" {
		t.Errorf("entries[0].Service: got %s, want EC2", d.Entries[0].Service)
	}
	if d.Entries[0].PctChange != 20.0 {
		t.Errorf("entries[0].PctChange: got %f, want 20.0", d.Entries[0].PctChange)
	}
	if d.Entries[1].Service != "S3" {
		t.Errorf("entries[1].Service: got %s, want S3", d.Entries[1].Service)
	}
	if d.Entries[1].Delta != -5.0 {
		t.Errorf("entries[1].Delta: got %f, want -5.0", d.Entries[1].Delta)
	}
}

func TestWriteCostEmpty(t *testing.T) {
	type costOut struct {
		Diffs []json.RawMessage `json:"diffs"`
	}
	out := roundTrip[costOut](t, func(buf *bytes.Buffer) error {
		return WriteCost(buf, nil, nil)
	})
	if len(out.Diffs) != 0 {
		t.Errorf("diffs length: got %d, want 0", len(out.Diffs))
	}
}

func TestWriteCostMultipleProviders(t *testing.T) {
	diffs := []cloud.CostDiff{
		{Provider: "aws", TotalBefore: 200, TotalAfter: 210, TotalDelta: 10},
		{Provider: "gamma", TotalBefore: 80, TotalAfter: 75, TotalDelta: -5},
		{Provider: "beta", TotalBefore: 50, TotalAfter: 50, TotalDelta: 0},
	}

	type diffItem struct {
		Provider   string  `json:"Provider"`
		TotalDelta float64 `json:"TotalDelta"`
	}
	type costOut struct {
		Diffs []diffItem `json:"diffs"`
	}

	out := roundTrip[costOut](t, func(buf *bytes.Buffer) error {
		return WriteCost(buf, diffs, nil)
	})

	if len(out.Diffs) != 3 {
		t.Fatalf("diffs length: got %d, want 3", len(out.Diffs))
	}
	providers := []string{"aws", "gamma", "beta"}
	deltas := []float64{10, -5, 0}
	for i, d := range out.Diffs {
		if d.Provider != providers[i] {
			t.Errorf("diffs[%d].Provider: got %s, want %s", i, d.Provider, providers[i])
		}
		if d.TotalDelta != deltas[i] {
			t.Errorf("diffs[%d].TotalDelta: got %f, want %f", i, d.TotalDelta, deltas[i])
		}
	}
}

// TestReportsCarryIncompleteIndependentOfFlags pins the second half of the
// contract: the JSON `incomplete` array is populated at observation time, not on
// the same path as the stderr message.
//
// --quiet routes the provider's warning copy to io.Discard and --fail-on decides
// whether the run is a gate. Neither is allowed to reach the report: a script
// running `--quiet --output json` is exactly the consumer that has nothing but
// the payload to tell a clean account from an unreadable one.
func TestReportsCarryIncompleteIndependentOfFlags(t *testing.T) {
	incomplete := []string{"describe regions: AccessDenied; scanned us-east-1 only"}

	writers := map[string]func(w *bytes.Buffer) error{
		"certs":     func(w *bytes.Buffer) error { return WriteCerts(w, nil, incomplete) },
		"network":   func(w *bytes.Buffer) error { return WriteNetwork(w, nil, incomplete) },
		"tags":      func(w *bytes.Buffer) error { return WriteTags(w, nil, incomplete) },
		"secrets":   func(w *bytes.Buffer) error { return WriteSecrets(w, nil, incomplete) },
		"orphans":   func(w *bytes.Buffer) error { return WriteOrphans(w, nil, incomplete) },
		"quota":     func(w *bytes.Buffer) error { return WriteQuotas(w, nil, incomplete) },
		"inventory": func(w *bytes.Buffer) error { return WriteInventory(w, nil, incomplete) },
		"lambda":    func(w *bytes.Buffer) error { return WriteLambdaPolicy(w, nil, incomplete) },
		"cost":      func(w *bytes.Buffer) error { return WriteCost(w, nil, incomplete) },
		"drift":     func(w *bytes.Buffer) error { return WriteDrift(w, nil, incomplete) },
		"iam":       func(w *bytes.Buffer) error { return WriteIAM(w, nil, 0, 0, nil, incomplete) },
		"storage":   func(w *bytes.Buffer) error { return WriteStorage(w, nil, incomplete) },
	}

	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := write(&buf); err != nil {
				t.Fatalf("write: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			arr, ok := got["incomplete"].([]any)
			if !ok {
				t.Fatalf("report has no incomplete array; a partial scan reports as clean.\n%s", buf.String())
			}
			if len(arr) != 1 || !strings.Contains(arr[0].(string), "AccessDenied") {
				t.Errorf("incomplete array should carry the observation, got %v", arr)
			}
		})
	}
}

// A report with nothing unread must not carry an empty array — omitempty keeps
// "saw everything" and "saw nothing" textually distinct for a consumer.
// A complete scan states that it was complete, rather than saying nothing.
// Omitting the key made "I saw everything" indistinguishable from "I do not
// report coverage", which is the distinction the record exists to carry — and
// over MCP, where there is no exit code, it is the only thing carrying it.
// TestEveryEnvelopeAlwaysCarriesIncomplete holds this across every writer.
func TestCompleteScanReportsAnEmptyIncomplete(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCerts(&buf, nil, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	var envelope struct {
		Incomplete *[]string `json:"incomplete"`
	}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if envelope.Incomplete == nil {
		t.Fatalf("a complete scan omitted the incomplete key or emitted null: %s", buf.String())
	}
	if len(*envelope.Incomplete) != 0 {
		t.Errorf("a complete scan reported %d incompletions", len(*envelope.Incomplete))
	}
}

// Every JSON envelope carries `incomplete`, and a run that saw everything carries
// it as `[]`.
//
// Over MCP there is no exit code, so this array is the whole of what tells an
// agent the scan could not see the account. An omitted key and a `null` are the
// same ambiguity: neither can be told apart from a tool that does not report its
// own coverage. Emitting `[]` makes "I looked at everything" a positive
// statement.
//
// Observed, not analysed. What the caller receives is `[]` or it is `null`, so
// each writer is rendered and the bytes are read. Whether a writer normalizes
// through a helper, a wrapper, or a package this check has never heard of makes
// no difference to what comes back.
//
// The writers below are named by hand and the list checks itself against the
// package. writersTakingAWriter reads every exported function that renders to an
// io.Writer and reports an error, and the assertion at the end requires each one
// to be rendered here or to have a case in
// TestEverySARIFWriterCarriesTheIncompleteRecord — so the two gates partition the
// package's writers between them and a writer in neither fails.
//
// The population is a signature rather than a body or a name, because both of
// those are satisfied by spelling. A writer whose own body called writeJSON was
// the population once, and a writer rendering one frame down through a per-domain
// helper joined nothing while the assertion beside it claimed every exported JSON
// writer was covered.
//
// No writer is subtracted and there is no exemption list, so a writer whose
// envelope carries no coverage key fails here rather than being named and
// excused.
func TestEveryEnvelopeAlwaysCarriesIncomplete(t *testing.T) {
	exercised := map[string]func(io.Writer) error{
		"WriteCerts":        func(w io.Writer) error { return WriteCerts(w, nil, nil) },
		"WriteStorage":      func(w io.Writer) error { return WriteStorage(w, nil, nil) },
		"WriteNetwork":      func(w io.Writer) error { return WriteNetwork(w, nil, nil) },
		"WriteTags":         func(w io.Writer) error { return WriteTags(w, nil, nil) },
		"WriteSecrets":      func(w io.Writer) error { return WriteSecrets(w, nil, nil) },
		"WriteOrphans":      func(w io.Writer) error { return WriteOrphans(w, nil, nil) },
		"WriteQuotas":       func(w io.Writer) error { return WriteQuotas(w, nil, nil) },
		"WriteInventory":    func(w io.Writer) error { return WriteInventory(w, nil, nil) },
		"WriteCost":         func(w io.Writer) error { return WriteCost(w, nil, nil) },
		"WriteDrift":        func(w io.Writer) error { return WriteDrift(w, nil, nil) },
		"WriteLambdaPolicy": func(w io.Writer) error { return WriteLambdaPolicy(w, nil, nil) },
		"WritePlatform":     func(w io.Writer) error { return WritePlatform(w, nil, nil) },
		"WriteIAM":          func(w io.Writer) error { return WriteIAM(w, nil, 0, 0, nil, nil) },
		"WriteK8sFindings":  func(w io.Writer) error { return WriteK8sFindings(w, nil, nil) },
		"WriteRepo":         func(w io.Writer) error { return WriteRepo(w, nil, nil) },
		"WriteCompare":      func(w io.Writer) error { return WriteCompare(w, nil, nil, nil, nil) },
		// These two carry the record on the value they marshal rather than
		// taking it as an argument, which is how they sat outside a denominator
		// that counted the argument — and they were the two that emitted null.
		"WriteCompliance": func(w io.Writer) error {
			return WriteCompliance(w, compliance.ComplianceReport{Benchmark: "cis-aws-v3"})
		},
		"WriteAudit": func(w io.Writer) error { return WriteAudit(w, &audit.Report{}) },
	}

	for name, write := range exercised {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := write(&buf); err != nil {
				t.Fatalf("write %s report: %v", name, err)
			}
			body := buf.String()
			if !strings.Contains(body, `"incomplete"`) {
				t.Fatalf("%s omits the incomplete key entirely:\n%s", name, body)
			}

			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
				t.Fatalf("%s report is not valid JSON: %v", name, err)
			}
			raw, ok := envelope["incomplete"]
			if !ok {
				t.Fatalf("%s decoded without an incomplete key", name)
			}
			if string(raw) == "null" {
				t.Errorf("%s emits incomplete as null; an agent cannot tell that from a tool "+
					"that does not report coverage", name)
			}

			var entries []string
			if err := json.Unmarshal(raw, &entries); err != nil {
				t.Fatalf("%s incomplete is not an array of strings: %v", name, err)
			}
			if len(entries) != 0 {
				t.Errorf("%s reported %d incompletions for a run given none", name, len(entries))
			}
		})
	}

	// Every writer this package exports is accounted for by name, not by count.
	//
	// A count is met by any set of the right size, so a writer joining while
	// another leaves reads as no change. Naming each one means a writer that
	// renders JSON through a helper — the shape a package acquires the moment two
	// writers share shaping code — fails here rather than sitting outside a
	// denominator that never noticed it.
	for _, name := range writersTakingAWriter(t) {
		_, rendered := exercised[name]
		_, isSARIF := sarifIncompleteWriters[name]
		switch {
		case rendered && isSARIF:
			t.Errorf("%s is exercised as a JSON envelope and as a SARIF writer; one of the two "+
				"is describing the wrong output", name)
		case !rendered && !isSARIF:
			t.Errorf("%s renders to an io.Writer and returns an error, and nothing observes "+
				"whether its output carries the unread record. Render it above, or give it a "+
				"case in TestEverySARIFWriterCarriesTheIncompleteRecord", name)
		}
	}

	// A name here that the package does not export renders nothing and hides that
	// the map has drifted from the tree.
	declared := map[string]bool{}
	for _, name := range writersTakingAWriter(t) {
		declared[name] = true
	}
	for name := range exercised {
		if !declared[name] {
			t.Errorf("this check renders %s, which internal/output does not export with that shape", name)
		}
	}
}

// writersTakingAWriter returns every exported function in this package that
// renders to an io.Writer and reports an error — the shape of a writer whose
// output a caller receives.
//
// The population is a signature, not a body and not a name. Reading each body for
// a writeJSON call put the population back inside the thing being checked: a
// writer that rendered through a per-domain helper called writeJSON one frame
// down and joined nothing, while the assertion beside it said every exported JSON
// writer was covered. A name prefix has the same defect one step out — it is
// satisfied by spelling.
//
// Which writers EXIST is a fact about the source, so it is read from there. What
// each one emits is not, which is why the map above renders every one of them and
// reads the bytes.
func writersTakingAWriter(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			if !takesWriterReturnsError(fn) {
				continue
			}
			out = append(out, fn.Name.Name)
		}
	}
	if len(out) == 0 {
		t.Fatal("no exported function in this package renders to an io.Writer; the population is broken, not the package")
	}
	return out
}

// takesWriterReturnsError reports whether fn's first parameter is an io.Writer
// and its only result is an error.
//
// A function that renders somewhere a caller can read has to be handed the
// destination, and a function that can fail to render has to say so. Together
// those exclude the constructors and the table helpers without asking what any of
// them is called: IncompleteNote writes to an io.Writer and returns nothing, so a
// caller cannot learn that it failed, and it is checked where its own shape can be
// asserted rather than as an envelope.
func takesWriterReturnsError(fn *ast.FuncDecl) bool {
	params := fn.Type.Params
	if params == nil || len(params.List) == 0 {
		return false
	}
	first, isSelector := params.List[0].Type.(*ast.SelectorExpr)
	if !isSelector || first.Sel == nil || first.Sel.Name != "Writer" {
		return false
	}
	if pkg, isIdent := first.X.(*ast.Ident); !isIdent || pkg.Name != "io" {
		return false
	}
	results := fn.Type.Results
	if results == nil || len(results.List) != 1 {
		return false
	}
	result, isIdent := results.List[0].Type.(*ast.Ident)
	return isIdent && result.Name == "error"
}
