package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/iam"
	"github.com/nanohype/cloudgov/internal/output"
)

// boundedIAMProvider is a provider whose audit log retains a fixed number of
// days. It answers a wider request with the data it has and returns success,
// which is what CloudTrail's Event history does: nothing about the call failing
// tells the scanner it got a narrower answer than it asked for.
type boundedIAMProvider struct {
	retentionDays int
}

func (b *boundedIAMProvider) Name() string                  { return "bounded" }
func (b *boundedIAMProvider) Detect(_ context.Context) bool { return true }
func (b *boundedIAMProvider) MaxLookbackDays() int          { return b.retentionDays }

func (b *boundedIAMProvider) ListPrincipals(_ context.Context) ([]cloud.Principal, error) {
	return []cloud.Principal{{ID: "AIDA1", Name: "svc-etl", Type: cloud.PrincipalRole, Provider: "bounded"}}, nil
}

func (b *boundedIAMProvider) GrantedPermissions(_ context.Context, _ cloud.Principal) ([]cloud.Permission, error) {
	return []cloud.Permission{{Action: "s3:PutObject", Resource: "*"}}, nil
}

func (b *boundedIAMProvider) UsedPermissions(_ context.Context, _ cloud.Principal, _ time.Time) ([]cloud.Permission, error) {
	return []cloud.Permission{{Action: "s3:GetObject", Resource: "*"}}, nil
}

func (b *boundedIAMProvider) MinimalPolicy(_ context.Context, _ cloud.Principal, _ []cloud.Permission) (cloud.Policy, error) {
	return cloud.Policy{}, nil
}

// The rendered report answers "what window is this?" without parsing a sentence.
//
// A consumer deciding whether a finding is safe to act on — `iam fix` is the one
// in this repository — reads the report, not the scan. With the window only
// inside each finding's Detail, recovering the premise means parsing prose, and
// the prose was the overstated half.
//
// The field and the prose are rendered from one value, so this asserts they agree
// rather than that both were remembered: the number the report's window carries
// is the number in every non-use finding beside it. It is checked on the bytes a
// consumer receives, not on the scan result, because that is what a consumer has.
func TestIAMReportCarriesTheWindowAConsumerReads(t *testing.T) {
	provider := &boundedIAMProvider{retentionDays: 90}

	res, err := iam.Scan(context.Background(), provider, iam.ScanOptions{
		Days: 365, MinSeverity: cloud.SeverityLow, Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var buf bytes.Buffer
	if err := output.WriteIAM(&buf, res.Findings, res.Principals, res.Scanned,
		res.UsedPermissions, res.Incomplete, res.Window); err != nil {
		t.Fatalf("render: %v", err)
	}

	var envelope struct {
		Window struct {
			RequestedDays int    `json:"requested_days"`
			ObservedDays  int    `json:"observed_days"`
			LimitedBy     string `json:"limited_by"`
		} `json:"window"`
		Findings []struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}

	if envelope.Window.ObservedDays != 90 {
		t.Errorf("window.observed_days = %d, want 90 — the report does not carry what it covered",
			envelope.Window.ObservedDays)
	}
	if envelope.Window.RequestedDays != 365 {
		t.Errorf("window.requested_days = %d, want 365 — a reader cannot tell the window was narrowed",
			envelope.Window.RequestedDays)
	}
	if envelope.Window.LimitedBy == "" {
		t.Error("window.limited_by is empty on a narrowed window, so nothing names what bounded it")
	}

	var claims int
	for _, f := range envelope.Findings {
		if f.Type != string(cloud.FindingUnusedPermission) && f.Type != string(cloud.FindingStalePrincipal) {
			continue
		}
		claims++
		if !strings.Contains(f.Detail, strconv.Itoa(envelope.Window.ObservedDays)) {
			t.Errorf("finding detail %q does not agree with the report's own window of %d days",
				f.Detail, envelope.Window.ObservedDays)
		}
		if strings.Contains(f.Detail, "the last "+strconv.Itoa(envelope.Window.RequestedDays)+" days") {
			t.Errorf("finding detail %q asserts the requested window; the report covered %d days",
				f.Detail, envelope.Window.ObservedDays)
		}
	}
	if claims == 0 {
		t.Fatal("the report carries no finding that claims a window, so nothing above was compared")
	}

	// The window is readable without gating on anything. A consumer that never
	// passes --fail-on still has to be able to tell what period the report rests
	// on, so the field carries it whether or not the run treats a short window as
	// a reason to stop.
	if !bytes.Contains(buf.Bytes(), []byte(`"window"`)) {
		t.Error("the envelope has no window key")
	}
}
