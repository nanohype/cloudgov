package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/compliance"
)

// runCompliance decides whether an auditor is told a CIS or SOC 2 control
// passed, and a verdict is the one output a reader cannot re-derive for
// themselves. It reached this file at 0% — every branch below was a decision
// nobody had watched the tool make.
//
// These drive the handler itself rather than the evaluator underneath it. The
// evaluator is covered in internal/compliance; what is only decided here is
// which reports are loaded, how each report's unread record is labelled, which
// exit code the run leaves behind, and what the artifact says.

// complianceRun resets the handler's flag state, runs it, and returns the exit
// code, the artifact written to --output-file, and what went to stderr.
//
// The artifact is read from a file rather than from a swapped os.Stdout because
// --output-file is the path an operator keeps, and it is the one this command
// renders its verdicts to when a run is being recorded.
type complianceRun struct {
	exit     int
	artifact string
	stderr   string
	err      error
}

type complianceFlags struct {
	benchmark  string
	format     string
	failOn     string
	quiet      bool
	iam        string
	storage    string
	network    string
	certs      string
	tags       string
	outputFile string // empty means the helper picks one under t.TempDir()
	noOutput   bool   // render to stdout, for the create-failure and format cases
}

func runComplianceWith(t *testing.T, f complianceFlags) complianceRun {
	t.Helper()
	restoreRunState(t)

	prevOut, prevFile := complianceOutputFmt, complianceOutputFile
	prevIAM, prevStorage := complianceIAMReport, complianceStorageReport
	prevNetwork, prevCerts, prevTags := complianceNetworkReport, complianceCertsReport, complianceTagsReport
	t.Cleanup(func() {
		complianceOutputFmt, complianceOutputFile = prevOut, prevFile
		complianceIAMReport, complianceStorageReport = prevIAM, prevStorage
		complianceNetworkReport, complianceCertsReport, complianceTagsReport = prevNetwork, prevCerts, prevTags
	})

	exitCode, failOn, quiet = 0, f.failOn, f.quiet
	complianceOutputFmt = f.format
	if complianceOutputFmt == "" {
		complianceOutputFmt = "table"
	}
	complianceIAMReport, complianceStorageReport = f.iam, f.storage
	complianceNetworkReport, complianceCertsReport, complianceTagsReport = f.network, f.certs, f.tags

	complianceOutputFile = f.outputFile
	if complianceOutputFile == "" && !f.noOutput {
		complianceOutputFile = filepath.Join(t.TempDir(), "report.out")
	}

	stderr := captureStderr(t)
	err := runCompliance(nil, []string{f.benchmark})
	captured := stderr()

	var artifact string
	if complianceOutputFile != "" {
		if b, readErr := os.ReadFile(complianceOutputFile); readErr == nil {
			artifact = string(b)
		}
	}
	return complianceRun{exit: exitCode, artifact: artifact, stderr: captured, err: err}
}

// captureStderr redirects os.Stderr for the duration of one call and returns a
// function yielding what was written. The handler's summary line and the
// incomplete block both go there, and both are claims this test checks.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prev := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if readErr != nil {
				break
			}
		}
		done <- sb.String()
	}()

	return func() string {
		os.Stderr = prev
		_ = w.Close()
		out := <-done
		_ = r.Close()
		return out
	}
}

func writeReport(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// An IAM report carrying one admin-access finding and one unread principal. The
// finding is what makes CIS 1.16 decidable; the incomplete entry is what must
// survive into the benchmark's own record.
const iamReportWithUnread = `{
  "findings": [{"Severity":"CRITICAL","Type":"ADMIN_ACCESS","Provider":"aws","Resource":"arn:aws:iam:::role/r","Detail":"attached AdministratorAccess"}],
  "total": 1,
  "principals_listed": 3,
  "principals_scanned": 2,
  "incomplete": ["principal ops-role: used permissions: AccessDenied"]
}`

func TestRunCompliance_RefusesAnUnrenderableFormatBeforeReadingAnything(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	got := runComplianceWith(t, complianceFlags{
		benchmark: "cis-aws-v3",
		format:    "yaml",
		iam:       missing,
		noOutput:  true,
	})
	if got.err == nil {
		t.Fatal("an unrenderable --output was accepted")
	}
	if !strings.Contains(got.err.Error(), "yaml") {
		t.Errorf("the refusal does not name the format it refused: %v", got.err)
	}
	// The report path does not exist, so a run that read it first would fail
	// with a read error instead. Failing on the flag is what proves the order.
	if strings.Contains(got.err.Error(), "does-not-exist") {
		t.Errorf("the format was validated after the report was read: %v", got.err)
	}
}

func TestRunCompliance_RefusesAnUnknownBenchmarkNamingTheOnesItHas(t *testing.T) {
	got := runComplianceWith(t, complianceFlags{benchmark: "pci-dss", noOutput: true})
	if got.err == nil {
		t.Fatal("an unknown benchmark was accepted")
	}
	for _, want := range compliance.AvailableBenchmarks() {
		if !strings.Contains(got.err.Error(), want) {
			t.Errorf("the refusal does not offer %q: %v", want, got.err)
		}
	}
}

func TestRunCompliance_BenchmarkIDIsCaseInsensitive(t *testing.T) {
	got := runComplianceWith(t, complianceFlags{benchmark: "CIS-AWS-V3", format: "json"})
	if got.err != nil {
		t.Fatalf("an upper-case benchmark id was refused: %v", got.err)
	}
	if got.artifact == "" {
		t.Error("no artifact was written")
	}
}

// The five report flags are five separate branches, and each labels its unread
// entries with the domain they came from. A benchmark's incomplete record is
// read by someone deciding whether to trust a control, so an entry that does not
// say which scan could not see is a record they cannot act on.
func TestRunCompliance_EachReportLabelsItsOwnUnreadRecord(t *testing.T) {
	tests := []struct {
		flag  string
		body  string
		label string
	}{
		{"iam", `{"findings":[],"total":0,"incomplete":["denied"]}`, "iam scan report: denied"},
		{"storage", `{"findings":[],"total":0,"incomplete":["denied"]}`, "storage audit report: denied"},
		{"network", `{"findings":[],"total":0,"incomplete":["denied"]}`, "network audit report: denied"},
		{"certs", `{"findings":[],"total":0,"incomplete":["denied"]}`, "certs report: denied"},
		{"tags", `{"findings":[],"total":0,"incomplete":["denied"]}`, "tags report: denied"},
	}

	for _, tc := range tests {
		t.Run(tc.flag, func(t *testing.T) {
			path := writeReport(t, tc.flag+".json", tc.body)
			f := complianceFlags{benchmark: "cis-aws-v3", format: "json"}
			switch tc.flag {
			case "iam":
				f.iam = path
			case "storage":
				f.storage = path
			case "network":
				f.network = path
			case "certs":
				f.certs = path
			case "tags":
				f.tags = path
			}

			got := runComplianceWith(t, f)
			if got.err != nil {
				t.Fatalf("unexpected error: %v", got.err)
			}

			var envelope struct {
				Incomplete []string `json:"incomplete"`
			}
			if err := json.Unmarshal([]byte(got.artifact), &envelope); err != nil {
				t.Fatalf("artifact is not JSON: %v (%s)", err, got.artifact)
			}
			var found bool
			for _, entry := range envelope.Incomplete {
				if entry == tc.label {
					found = true
				}
			}
			if !found {
				t.Errorf("the %s report's unread record did not reach the benchmark labelled as its own: %v",
					tc.flag, envelope.Incomplete)
			}
		})
	}
}

func TestRunCompliance_AReportItCannotReadIsAnError(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"malformed json", `{"findings":`},
		{"wrong shape", `"a string, not a report"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runComplianceWith(t, complianceFlags{
				benchmark: "cis-aws-v3",
				iam:       writeReport(t, "iam.json", tc.body),
				noOutput:  true,
			})
			if got.err == nil {
				t.Fatal("a report that could not be parsed was accepted; the benchmark would be evaluated over nothing and say nothing about it")
			}
		})
	}
}

func TestRunCompliance_AMissingReportPathIsAnError(t *testing.T) {
	got := runComplianceWith(t, complianceFlags{
		benchmark: "cis-aws-v3",
		iam:       filepath.Join(t.TempDir(), "absent.json"),
		noOutput:  true,
	})
	if got.err == nil {
		t.Fatal("a report path that does not exist was accepted")
	}
}

// The exit code is this command's contract with a merge gate. Each row is a
// different thing the run could not say, and a different number.
func TestRunCompliance_ExitCode(t *testing.T) {
	failing := writeReport(t, "iam.json", iamReportWithUnread)
	clean := writeReport(t, "iam-clean.json", `{"findings":[],"total":0,"incomplete":[]}`)

	tests := []struct {
		name   string
		failOn string
		iam    string
		want   int
		why    string
	}{
		{
			name: "informational run stays 0", failOn: "", iam: failing, want: 0,
			why: "without --fail-on the run is informational; findings and unevaluated controls both leave the code alone",
		},
		{
			name: "a failed control at the threshold is 2", failOn: "CRITICAL", iam: failing, want: 2,
			why: "CIS 1.16 fails on the admin-access finding and its severity is CRITICAL",
		},
		{
			name: "controls nobody could evaluate are 3", failOn: "CRITICAL", iam: clean, want: 3,
			why: "no control is decidable from an empty report, and a benchmark that decided nothing must not read as one that passed",
		},
		{
			name: "no reports at all is 3", failOn: "LOW", iam: "", want: 3,
			why: "every control is unevaluated, which is the case the guard exists for",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runComplianceWith(t, complianceFlags{
				benchmark: "cis-aws-v3", failOn: tc.failOn, iam: tc.iam, format: "json",
			})
			if got.err != nil {
				t.Fatalf("unexpected error: %v", got.err)
			}
			if got.exit != tc.want {
				t.Errorf("exit = %d, want %d — %s", got.exit, tc.want, tc.why)
			}
		})
	}
}

// A real failure outranks "could not tell". Both are true of the same run: the
// admin-access finding fails CIS 1.16 and eighteen other controls are
// undecidable, and the caller needs the stronger of the two.
func TestRunCompliance_AFailedControlOutranksAnUnevaluatedOne(t *testing.T) {
	got := runComplianceWith(t, complianceFlags{
		benchmark: "cis-aws-v3",
		failOn:    "CRITICAL",
		iam:       writeReport(t, "iam.json", iamReportWithUnread),
		format:    "json",
	})
	if got.err != nil {
		t.Fatalf("unexpected error: %v", got.err)
	}
	if got.exit != 2 {
		t.Fatalf("exit = %d, want 2 — a benchmark with both a failed control and undecidable ones reports the failure", got.exit)
	}

	var envelope struct {
		Summary struct {
			Failed       int `json:"failed"`
			NotEvaluated int `json:"not_evaluated"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(got.artifact), &envelope); err != nil {
		t.Fatalf("artifact is not JSON: %v", err)
	}
	if envelope.Summary.Failed == 0 || envelope.Summary.NotEvaluated == 0 {
		t.Fatalf("this test needs a run with both a failure and an undecidable control; got failed=%d not_evaluated=%d",
			envelope.Summary.Failed, envelope.Summary.NotEvaluated)
	}
}

// The summary line names two numbers because the benchmark's size and the
// number of controls this run could decide are different facts. Printing the
// benchmark's size alone reported a run that decided nothing as one that decided
// everything.
func TestRunCompliance_TheSummaryLineCountsWhatWasDecided(t *testing.T) {
	tests := []struct {
		name string
		iam  string
		want string
	}{
		{"nothing decidable", "", "0 of 22 controls evaluated"},
		{"some decidable", iamReportWithUnread, "4 of 22 controls evaluated"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := complianceFlags{benchmark: "cis-aws-v3"}
			if tc.iam != "" {
				f.iam = writeReport(t, "iam.json", tc.iam)
			}
			got := runComplianceWith(t, f)
			if got.err != nil {
				t.Fatalf("unexpected error: %v", got.err)
			}
			if !strings.Contains(got.stderr, tc.want) {
				t.Errorf("the summary line does not say %q; it said:\n%s", tc.want, got.stderr)
			}
		})
	}
}

func TestRunCompliance_QuietSilencesTheSummaryAndNotTheRecord(t *testing.T) {
	got := runComplianceWith(t, complianceFlags{
		benchmark: "cis-aws-v3",
		quiet:     true,
		iam:       writeReport(t, "iam.json", iamReportWithUnread),
	})
	if got.err != nil {
		t.Fatalf("unexpected error: %v", got.err)
	}
	if strings.Contains(got.stderr, "controls evaluated") {
		t.Errorf("--quiet did not silence the summary line: %s", got.stderr)
	}
	// --quiet silences the copy on stderr, not the record. The artifact is what
	// an operator keeps, and it still has to say the inputs were partial.
	if !strings.Contains(got.artifact, "AccessDenied") {
		t.Errorf("--quiet removed the unread record from the artifact:\n%s", got.artifact)
	}
}

// The table is the artifact a reader keeps, and --output-file keeps only stdout.
// A saved table stating which controls passed and carrying nothing about the
// partial scans behind them is the shape the incomplete record exists to prevent.
func TestRunCompliance_TheSavedTableCarriesItsOwnCoverage(t *testing.T) {
	t.Run("partial inputs are named in the artifact", func(t *testing.T) {
		got := runComplianceWith(t, complianceFlags{
			benchmark: "cis-aws-v3",
			iam:       writeReport(t, "iam.json", iamReportWithUnread),
		})
		if got.err != nil {
			t.Fatalf("unexpected error: %v", got.err)
		}
		if !strings.Contains(got.artifact, "ops-role") {
			t.Errorf("the saved table does not name what the scan behind it could not read:\n%s", got.artifact)
		}
	})

	t.Run("whole inputs say so positively", func(t *testing.T) {
		got := runComplianceWith(t, complianceFlags{
			benchmark: "cis-aws-v3",
			iam:       writeReport(t, "iam.json", `{"findings":[],"total":0,"incomplete":[]}`),
		})
		if got.err != nil {
			t.Fatalf("unexpected error: %v", got.err)
		}
		// The positive control on the assertion above: without this, a renderer
		// that printed the note unconditionally would pass it.
		if strings.Contains(got.artifact, "could not be completed") {
			t.Errorf("a run whose inputs were whole reported observations it could not complete:\n%s", got.artifact)
		}
	})
}

func TestRunCompliance_EveryFormatRendersTheSameVerdicts(t *testing.T) {
	iam := writeReport(t, "iam.json", iamReportWithUnread)

	tests := []struct {
		format string
		wants  []string
	}{
		{"table", []string{"1.16", "FAIL"}},
		{"json", []string{`"benchmark"`, `"results"`, `"incomplete"`, `"1.16"`}},
		{"sarif", []string{`"$schema"`, `"runs"`, `"toolExecutionNotifications"`}},
	}
	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			got := runComplianceWith(t, complianceFlags{
				benchmark: "cis-aws-v3", format: tc.format, iam: iam,
			})
			if got.err != nil {
				t.Fatalf("unexpected error: %v", got.err)
			}
			for _, want := range tc.wants {
				if !strings.Contains(got.artifact, want) {
					t.Errorf("the %s artifact does not carry %q:\n%s", tc.format, want, got.artifact)
				}
			}
		})
	}
}

func TestRunCompliance_AnUnwritableOutputFileIsAnError(t *testing.T) {
	// A directory where the file should be: os.Create refuses it, and the run
	// must surface that rather than rendering to nowhere.
	dir := filepath.Join(t.TempDir(), "occupied")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	got := runComplianceWith(t, complianceFlags{
		benchmark: "cis-aws-v3", outputFile: dir,
	})
	if got.err == nil {
		t.Fatal("an unwritable --output-file was accepted")
	}
	if !strings.Contains(got.err.Error(), "create output file") {
		t.Errorf("the refusal does not say what it could not do: %v", got.err)
	}
}

// Both published benchmarks are reachable through this handler. A benchmark
// registered in internal/compliance and unreachable here is a control set the
// CLI advertises and cannot run.
func TestRunCompliance_EveryPublishedBenchmarkIsReachable(t *testing.T) {
	available := compliance.AvailableBenchmarks()
	if len(available) == 0 {
		t.Fatal("no benchmarks are published; this test is asserting against an empty set")
	}
	for _, id := range available {
		t.Run(id, func(t *testing.T) {
			got := runComplianceWith(t, complianceFlags{benchmark: id, format: "json"})
			if got.err != nil {
				t.Fatalf("benchmark %q is published and this handler cannot run it: %v", id, got.err)
			}
			var envelope struct {
				Benchmark string `json:"benchmark"`
				Results   []struct {
					Control struct {
						ID string `json:"id"`
					} `json:"control"`
				} `json:"results"`
			}
			if err := json.Unmarshal([]byte(got.artifact), &envelope); err != nil {
				t.Fatalf("artifact is not JSON: %v", err)
			}
			if envelope.Benchmark == "" {
				t.Error("the artifact does not name the benchmark it evaluated")
			}
			if len(envelope.Results) == 0 {
				t.Errorf("benchmark %q rendered no control results", id)
			}
		})
	}
}
