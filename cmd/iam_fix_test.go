package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/fix"
)

// incompleteIAMReport is a saved scan that could not see part of the account:
// one finding, one principal it failed to read, and a window narrowed to less
// than was asked for.
//
// Both halves matter. The unread principal is a permission set the scan never
// compared against anything, and the short window means a permission last used
// before it looks unused. A fix built from this removes access on the strength
// of activity nobody observed.
const incompleteIAMReport = `{
  "findings": [
    {"severity":"HIGH","type":"UNUSED_PERMISSION","provider":"aws",
     "principal":{"id":"AIDA1","name":"svc-etl","type":"role","provider":"aws"},
     "resource":"*","detail":"s3:PutObject was not used in the 90 day(s) this scan covered (365 requested; aws retains no more)"}
  ],
  "total": 1,
  "principals_listed": 40,
  "principals_scanned": 31,
  "incomplete": [
    "principal svc-billing: granted permissions: AccessDenied",
    "audit-log lookback: 365 day(s) requested, 90 covered — aws retains no more, so nothing is known about the 275 day(s) before that"
  ],
  "window": {"requested_days": 365, "observed_days": 90, "limited_by": "aws"},
  "used_permissions": {"AIDA1": [{"action":"s3:GetObject","resource":"*"}]}
}`

// completeIAMReport is the same scan with nothing unread.
const completeIAMReport = `{
  "findings": [
    {"severity":"HIGH","type":"UNUSED_PERMISSION","provider":"aws",
     "principal":{"id":"AIDA1","name":"svc-etl","type":"role","provider":"aws"},
     "resource":"*","detail":"s3:PutObject was not used in the last 90 days"}
  ],
  "total": 1,
  "principals_listed": 40,
  "principals_scanned": 40,
  "incomplete": [],
  "window": {"requested_days": 90, "observed_days": 90},
  "used_permissions": {"AIDA1": [{"action":"s3:GetObject","resource":"*"}]}
}`

// stubIAMProvider generates a policy for any principal, so nothing about the
// provider stops a fix being written. That is the point: with a provider that
// works, the only thing standing between an incomplete report and a file on disk
// is the refusal, and removing it must produce a file.
type stubIAMProvider struct{}

func (stubIAMProvider) Name() string                  { return "aws" }
func (stubIAMProvider) Detect(_ context.Context) bool { return true }

func (stubIAMProvider) ListPrincipals(_ context.Context) ([]cloud.Principal, error) { return nil, nil }

func (stubIAMProvider) GrantedPermissions(_ context.Context, _ cloud.Principal) ([]cloud.Permission, error) {
	return nil, nil
}

func (stubIAMProvider) UsedPermissions(_ context.Context, _ cloud.Principal, _ time.Time) ([]cloud.Permission, error) {
	return nil, nil
}

func (stubIAMProvider) MinimalPolicy(_ context.Context, _ cloud.Principal, _ []cloud.Permission) (cloud.Policy, error) {
	return cloud.Policy{Raw: []byte(`{"Version":"2012-10-17","Statement":[]}`)}, nil
}

type iamFixRun struct {
	err     error
	written []string
	stderr  string
	outDir  string
}

// runIAMFixWith drives the generator with a working provider and returns what
// landed on disk.
//
// It goes through generateIAMFixes rather than runIAMFix so the write is
// reachable: runIAMFix resolves providers from the ambient AWS chain, and in a
// test with no credentials it fails before writing anything — which would make
// "no file appeared" true whether or not the refusal existed.
func runIAMFixWith(t *testing.T, reportBody, format string, accept bool) iamFixRun {
	t.Helper()
	restoreRunState(t)

	prevFrom, prevFormat, prevAccept := iamFromFile, iamFixFormat, iamFixAcceptIncomplete
	t.Cleanup(func() {
		iamFromFile, iamFixFormat, iamFixAcceptIncomplete = prevFrom, prevFormat, prevAccept
	})

	dir := t.TempDir()
	iamFromFile = filepath.Join(dir, "scan.json")
	if err := os.WriteFile(iamFromFile, []byte(reportBody), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	iamFixFormat = format
	iamFixAcceptIncomplete = accept

	var r iamFixReport
	if err := json.Unmarshal([]byte(reportBody), &r); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	outDir := filepath.Join(dir, "fixes")
	stderr := captureStderr(t)
	err := generateIAMFixes(context.Background(), r,
		[]cloud.IAMProvider{stubIAMProvider{}},
		fix.Options{OutputDir: outDir, Severity: cloud.SeverityHigh}, accept)
	captured := stderr()

	return iamFixRun{err: err, written: entriesUnder(t, outDir), stderr: captured, outDir: outDir}
}

// entriesUnder walks the output directory and returns every path in it. The
// directory not existing is the same answer as an empty one: nothing was
// written.
func entriesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			rel = path
		}
		out = append(out, rel)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// A fix is not a report, and the two do not get the same default.
//
// Reporting an incomplete scan costs an operator a re-read, so `iam scan` prints
// what it could not see and leaves the exit code to --fail-on. Generating a
// change from one costs them access that is in use: the removals are computed
// from the permissions the scan OBSERVED, so every permission it could not
// observe reads as unused.
//
// So `iam fix` refuses, and the refusal is measured by looking at the
// filesystem. An exit code is the command's own account of itself — a fix that
// wrote files and then reported failure has already done the damage, and a test
// reading only the code would call that a pass.
func TestIAMFix_RefusesAnIncompleteScanAndWritesNothing(t *testing.T) {
	run := runIAMFixWith(t, incompleteIAMReport, "terraform", false)

	if len(run.written) != 0 {
		t.Fatalf("a fix was generated from a partial scan: %v", run.written)
	}
	if _, err := os.Stat(run.outDir); !os.IsNotExist(err) {
		t.Errorf("the output directory exists after a refusal (%v); the run should touch nothing "+
			"before deciding it should not act", err)
	}
	if run.err == nil {
		t.Fatal("the refusal returned no error, so a caller cannot tell it did not act")
	}

	// The refusal names what was missing, what the removals would have rested
	// on, and both ways forward. A refusal naming none of them leaves the
	// operator with a command that merely stopped.
	msg := run.err.Error()
	for _, want := range []string{
		"svc-billing",
		"90 day(s)",
		"365",
		"--accept-incomplete-scan",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, msg)
		}
	}
}

// The opt-out is a different flag from --fail-on on purpose: --fail-on asks what
// severity should make a run exit non-zero, which is a question about reporting.
// Overloading it would make an operator raising a reporting threshold silently
// authorise a remediation.
func TestIAMFix_AcceptFlagIsNotFailOn(t *testing.T) {
	restoreRunState(t)
	prev := iamFixAcceptIncomplete
	t.Cleanup(func() { iamFixAcceptIncomplete = prev })

	if iamFixCmd.Flags().Lookup("accept-incomplete-scan") == nil {
		t.Fatal("iam fix has no --accept-incomplete-scan flag, so the only way past the refusal " +
			"would be a flag that means something else")
	}
	// The property, not the flag plumbing: a run with a reporting threshold set
	// and no acceptance still writes nothing. An operator raising --fail-on was
	// answering a question about reporting and was not asked about remediation.
	failOn = "CRITICAL"
	iamFixAcceptIncomplete = false
	run := runIAMFixWith(t, incompleteIAMReport, "terraform", false)
	if len(run.written) != 0 {
		t.Errorf("a fix was generated with only a reporting flag set: %v", run.written)
	}
}

// With the opt-out set the change is written, and it says what it was built
// from.
//
// The caveat travels in the generated files rather than on stderr. A fix file
// outlives the run that produced it: it is reviewed later, in a pull request, by
// someone who never saw the command. A warning printed once at the terminal is
// gone by then, and what is left is a diff removing permissions with nothing to
// say the evidence was partial.
func TestIAMFix_AcceptedIncompleteScanIsRecordedInTheFiles(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		carrier   func(written []string) string
		mustExist string
	}{
		{
			// Terraform has comments, so the caveat heads every generated file
			// and cannot be separated from the change it qualifies.
			name:      "terraform",
			format:    "terraform",
			mustExist: "minimal_svc_etl.tf",
		},
		{
			// A raw IAM policy has no comment syntax and anything added to it
			// stops being a policy, so the caveat is a file beside them, named to
			// sort ahead and to read as a warning in a listing.
			name:      "json",
			format:    "json",
			mustExist: "AAA-PARTIAL-SCAN-README.txt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			run := runIAMFixWith(t, incompleteIAMReport, tc.format, true)
			if run.err != nil {
				t.Fatalf("accepted run returned an error: %v", run.err)
			}
			if len(run.written) == 0 {
				t.Fatal("the operator accepted the incomplete scan and nothing was written")
			}

			var found bool
			for _, w := range run.written {
				if w == tc.mustExist {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s among %v", tc.mustExist, run.written)
			}

			// Read from disk, not from the value handed to the generator: what a
			// reviewer sees is the file.
			body, err := os.ReadFile(filepath.Join(run.outDir, tc.mustExist))
			if err != nil {
				t.Fatalf("read %s: %v", tc.mustExist, err)
			}
			text := string(body)

			for _, want := range []string{
				"PARTIAL SCAN",
				"svc-billing",
				"90 day(s)",
				"365",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("%s does not carry %q; a reviewer cannot tell the evidence was "+
						"partial:\n%s", tc.mustExist, want, text)
				}
			}
		})
	}
}

// A complete scan generates the same fix with no caveat. A banner on every file
// would be a warning that means nothing, and the one on a partial scan would
// stop being read.
func TestIAMFix_CompleteScanCarriesNoCaveat(t *testing.T) {
	run := runIAMFixWith(t, completeIAMReport, "terraform", false)
	if run.err != nil {
		t.Fatalf("a complete scan was refused: %v", run.err)
	}
	if len(run.written) == 0 {
		t.Fatal("a complete scan generated nothing")
	}

	for _, name := range run.written {
		body, err := os.ReadFile(filepath.Join(run.outDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(body), "PARTIAL SCAN") {
			t.Errorf("%s carries a partial-scan caveat over a scan that saw everything", name)
		}
	}
	for _, name := range run.written {
		if name == "AAA-PARTIAL-SCAN-README.txt" {
			t.Error("a complete scan wrote a partial-scan note")
		}
	}
}
