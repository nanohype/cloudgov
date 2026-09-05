package iam

import (
	"context"
	"errors"
	"strconv"
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

// boundedProvider is a provider whose audit log retains a fixed number of days,
// and which records the StartTime it was actually asked for.
//
// Recording it is the point: a provider bounded at 90 days answers a 365-day
// request with 90 days of data and returns success, so nothing about the call
// failing tells the scanner it got a narrower answer. The only way to know the
// window was narrowed is to look at what was asked.
type boundedProvider struct {
	mockIAMProvider
	retentionDays int
	askedSince    time.Time
}

func (b *boundedProvider) MaxLookbackDays() int { return b.retentionDays }

func (b *boundedProvider) UsedPermissions(ctx context.Context, p cloud.Principal, since time.Time) ([]cloud.Permission, error) {
	b.askedSince = since
	return b.mockIAMProvider.UsedPermissions(ctx, p, since)
}

// A scan never claims a window wider than the audit log behind it can answer
// for, and the report says which window it did cover.
//
// The unsafe direction is the cautious one: an operator about to remove a
// permission widens the window to be more certain, and the wider they ask the
// further past the evidence the claim goes. A permission last used 120 days ago
// is indistinguishable from one never used when the log holds 90, and the report
// used to state the stronger claim with more confidence the further out it went.
//
// Observed rather than read: the scan is run against a provider that retains
// less than it is asked for, and both the StartTime the provider received and
// the text of the finding are checked against the window the report carries.
func TestScan_NeverClaimsAWindowTheAuditLogCannotAnswer(t *testing.T) {
	principal := cloud.Principal{ID: "AIDA1", Name: "svc-etl", Type: cloud.PrincipalRole, Provider: "mock"}

	tests := []struct {
		name          string
		requestedDays int
		retentionDays int
		wantObserved  int
		wantShort     bool
	}{
		{
			name:          "asked for more than the log holds",
			requestedDays: 365,
			retentionDays: 90,
			wantObserved:  90,
			wantShort:     true,
		},
		{
			name:          "asked for exactly what the log holds",
			requestedDays: 90,
			retentionDays: 90,
			wantObserved:  90,
		},
		{
			name:          "asked for less than the log holds",
			requestedDays: 30,
			retentionDays: 90,
			wantObserved:  30,
		},
		{
			// A provider declaring no bound is unbounded: retention belongs to
			// the source, and a source that does not say has none imposed here.
			name:          "the provider declares no bound",
			requestedDays: 365,
			retentionDays: 0,
			wantObserved:  365,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &boundedProvider{
				mockIAMProvider: mockIAMProvider{
					principals: []cloud.Principal{principal},
					granted:    map[string][]cloud.Permission{"svc-etl": {{Action: "s3:PutObject", Resource: "*"}}},
					used:       map[string][]cloud.Permission{"svc-etl": {{Action: "s3:GetObject", Resource: "*"}}},
				},
				retentionDays: tc.retentionDays,
			}

			before := time.Now()
			res, err := Scan(context.Background(), p, ScanOptions{
				Days: tc.requestedDays, MinSeverity: cloud.SeverityLow, Concurrency: 1,
			})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			if res.Window.RequestedDays != tc.requestedDays {
				t.Errorf("window.requested_days = %d, want %d", res.Window.RequestedDays, tc.requestedDays)
			}
			if res.Window.ObservedDays != tc.wantObserved {
				t.Errorf("window.observed_days = %d, want %d", res.Window.ObservedDays, tc.wantObserved)
			}
			if res.Window.Short() != tc.wantShort {
				t.Errorf("window.Short() = %t, want %t", res.Window.Short(), tc.wantShort)
			}

			// What the provider was actually asked for, which is the thing the
			// report is a claim about. A window field that says 90 while the
			// query reached back 365 would be a second wrong number rather than
			// a fix.
			askedDays := int(before.Sub(p.askedSince).Hours()/24 + 0.5)
			if askedDays != tc.wantObserved {
				t.Errorf("the provider was queried from %d day(s) ago; the report says %d were covered",
					askedDays, res.Window.ObservedDays)
			}

			// Every finding that CLAIMS non-use states the covered window, never
			// the requested one. This is the assertion the branch exists for: an
			// operator reads the sentence, not the field.
			//
			// The population is the findings whose evidence is the audit log —
			// "not used in N days" and "no activity in N days". A wildcard-resource
			// or admin-access finding rests on the granted policy and makes no
			// claim about a period, so requiring a window in its prose would be
			// asserting one where none belongs.
			var windowClaims int
			for _, f := range res.Findings {
				if f.Type != cloud.FindingUnusedPermission && f.Type != cloud.FindingStalePrincipal {
					continue
				}
				windowClaims++
				if !strings.Contains(f.Detail, itoaTest(tc.wantObserved)) {
					t.Errorf("finding detail %q does not state the covered window of %d days",
						f.Detail, tc.wantObserved)
				}
				if tc.wantShort && strings.Contains(f.Detail, "the last "+itoaTest(tc.requestedDays)+" days") {
					t.Errorf("finding detail %q asserts the requested window over a scan that covered %d days",
						f.Detail, tc.wantObserved)
				}
			}
			if windowClaims == 0 {
				t.Fatal("the scan produced no finding that claims a window, so nothing above examined any prose")
			}

			// A short window is an observation the scan was asked to make and
			// could not, so it joins the unread record as well as the field.
			var noted bool
			for _, u := range res.Incomplete {
				if strings.Contains(u, "audit-log lookback") {
					noted = true
				}
			}
			if noted != tc.wantShort {
				t.Errorf("short window recorded as unread = %t, want %t: %v", noted, tc.wantShort, res.Incomplete)
			}
		})
	}
}

func itoaTest(n int) string {
	return strconv.Itoa(n)
}
