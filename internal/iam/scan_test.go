package iam

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// mockIAMProvider implements cloud.IAMProvider. Errors are keyed by principal
// name so a single scan can mix readable and unreadable principals — the case
// that matters, since a scan is only misleading when it partly succeeds.
type mockIAMProvider struct {
	principals []cloud.Principal
	granted    map[string][]cloud.Permission
	used       map[string][]cloud.Permission
	grantedErr map[string]error
	usedErr    map[string]error
}

func (m *mockIAMProvider) Name() string                  { return "mock" }
func (m *mockIAMProvider) Detect(_ context.Context) bool { return true }

func (m *mockIAMProvider) ListPrincipals(_ context.Context) ([]cloud.Principal, error) {
	return m.principals, nil
}

func (m *mockIAMProvider) GrantedPermissions(_ context.Context, p cloud.Principal) ([]cloud.Permission, error) {
	if err := m.grantedErr[p.Name]; err != nil {
		return nil, err
	}
	return m.granted[p.Name], nil
}

func (m *mockIAMProvider) UsedPermissions(_ context.Context, p cloud.Principal, _ time.Time) ([]cloud.Permission, error) {
	if err := m.usedErr[p.Name]; err != nil {
		return nil, err
	}
	return m.used[p.Name], nil
}

func (m *mockIAMProvider) MinimalPolicy(_ context.Context, _ cloud.Principal, _ []cloud.Permission) (cloud.Policy, error) {
	return cloud.Policy{}, nil
}

func scanOpts() ScanOptions {
	return ScanOptions{Days: 90, MinSeverity: cloud.SeverityLow, Concurrency: 2}
}

// TestScan_UnreadablePrincipalIsNotScanned pins the coverage claim. `Scanned`
// used to be the number of principals the scan set out to read, so a run that
// could read none of them still reported full coverage — and the JSON field is
// named principals_scanned, which a consumer reads as evidence of breadth.
func TestScan_UnreadablePrincipalIsNotScanned(t *testing.T) {
	denied := errors.New("AccessDenied")
	p := &mockIAMProvider{
		principals: []cloud.Principal{
			makePrincipal("1", "readable", "aws", nil),
			makePrincipal("2", "denied-grants", "aws", nil),
			makePrincipal("3", "denied-trail", "aws", nil),
		},
		granted: map[string][]cloud.Permission{
			"readable":     {perm("s3:GetObject", "*")},
			"denied-trail": {perm("s3:GetObject", "*")},
		},
		used:       map[string][]cloud.Permission{"readable": {perm("s3:GetObject", "*")}},
		grantedErr: map[string]error{"denied-grants": denied},
		usedErr:    map[string]error{"denied-trail": denied},
	}

	res, err := Scan(context.Background(), p, scanOpts())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if res.Principals != 3 {
		t.Errorf("Principals counts what exists: got %d want 3", res.Principals)
	}
	if res.Scanned != 1 {
		t.Errorf("Scanned counts what was analyzed: got %d want 1", res.Scanned)
	}
	if len(res.Incomplete) != 2 {
		t.Fatalf("expected both unreadable principals recorded, got %v", res.Incomplete)
	}
	for _, want := range []string{"denied-grants", "denied-trail"} {
		var found bool
		for _, inc := range res.Incomplete {
			if strings.Contains(inc, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no incompletion names %s: %v", want, res.Incomplete)
		}
	}
}

// TestScan_UnreadableTrailDoesNotInventFindings is the sharper half. A dropped
// UsedPermissions error is worse than a missing finding: analyze() reads an
// empty used-set as "never used", so continuing would report the principal as
// stale and every one of its permissions as unused — confident findings derived
// from data the scan never obtained.
func TestScan_UnreadableTrailDoesNotInventFindings(t *testing.T) {
	p := &mockIAMProvider{
		principals: []cloud.Principal{makePrincipal("1", "busy-role", "aws", nil)},
		granted: map[string][]cloud.Permission{
			"busy-role": {perm("s3:GetObject", "arn:aws:s3:::data/*"), perm("sqs:SendMessage", "arn:aws:sqs:us-west-2:111111111111:q")},
		},
		usedErr: map[string]error{"busy-role": errors.New("ThrottlingException")},
	}

	res, err := Scan(context.Background(), p, scanOpts())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("an unread CloudTrail history must produce no findings, got %+v", res.Findings)
	}
	if containsType(res.Findings, cloud.FindingStalePrincipal) {
		t.Error("reported a stale principal from a CloudTrail query that never returned")
	}
	if len(res.Incomplete) != 1 {
		t.Errorf("expected the throttle recorded, got %v", res.Incomplete)
	}
}

// TestScan_CompleteRunReportsNothingIncomplete: the signal has to be quiet when
// the scan really did see everything, or it means nothing.
func TestScan_CompleteRunReportsNothingIncomplete(t *testing.T) {
	p := &mockIAMProvider{
		principals: []cloud.Principal{makePrincipal("1", "readable", "aws", nil)},
		granted:    map[string][]cloud.Permission{"readable": {perm("s3:GetObject", "arn:aws:s3:::data/*")}},
		used:       map[string][]cloud.Permission{"readable": {perm("s3:GetObject", "arn:aws:s3:::data/*")}},
	}

	res, err := Scan(context.Background(), p, scanOpts())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Incomplete) != 0 {
		t.Errorf("a complete scan must report nothing incomplete, got %v", res.Incomplete)
	}
	if res.Scanned != 1 {
		t.Errorf("Scanned: got %d want 1", res.Scanned)
	}
}

// TestScan_ProgressReportsAttemptsNotSuccesses: the progress bar counts work
// done, so its denominator stays the number of principals to attempt even as
// Scanned drops.
func TestScan_ProgressReportsAttemptsNotSuccesses(t *testing.T) {
	p := &mockIAMProvider{
		principals: []cloud.Principal{
			makePrincipal("1", "a", "aws", nil),
			makePrincipal("2", "b", "aws", nil),
		},
		grantedErr: map[string]error{"a": errors.New("AccessDenied"), "b": errors.New("AccessDenied")},
	}

	opts := scanOpts()
	// Progress fires from the worker goroutines, so this has to be atomic.
	var lastTotal atomic.Int64
	opts.Progress = func(_, total int) { lastTotal.Store(int64(total)) }

	res, err := Scan(context.Background(), p, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if lastTotal.Load() != 2 {
		t.Errorf("progress total is the attempt count: got %d want 2", lastTotal.Load())
	}
	if res.Scanned != 0 {
		t.Errorf("nothing was readable, so nothing was scanned: got %d", res.Scanned)
	}
}
