package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCompare decides whether a finding that was not observed is reported as
// unread or as RESOLVED, and RESOLVED is the answer an operator acts on by
// closing the ticket. The wiring that carries both inputs' records into the
// result was held by nothing: no test drove this handler, so every claim about
// it — in the README, in the handler's own comments — rested on reading the
// code.
//
// These run it. Each case asserts what came out, not which calls appear in the
// source.

type compareRun struct {
	exit     int
	artifact string
	stderr   string
	err      error
}

func runCompareWith(t *testing.T, from, to, format, threshold string) compareRun {
	t.Helper()
	restoreRunState(t)

	prevFrom, prevTo := compareFrom, compareTo
	prevBaseline, prevCurrent := compareBaseline, compareCurrent
	prevFmt, prevFile := compareOutputFmt, compareOutputFile
	t.Cleanup(func() {
		compareFrom, compareTo = prevFrom, prevTo
		compareBaseline, compareCurrent = prevBaseline, prevCurrent
		compareOutputFmt, compareOutputFile = prevFmt, prevFile
	})

	// Named threshold, not failOn: a parameter spelled like the package variable
	// assigns itself and the gate never sees the flag.
	exitCode, failOn, quiet = 0, threshold, false
	compareBaseline, compareCurrent = "", ""
	compareFrom, compareTo = from, to
	compareOutputFmt = format
	if compareOutputFmt == "" {
		compareOutputFmt = "table"
	}
	compareOutputFile = filepath.Join(t.TempDir(), "compare.out")

	stderr := captureStderr(t)
	err := runCompare(nil, nil)
	captured := stderr()

	var artifact string
	if b, readErr := os.ReadFile(compareOutputFile); readErr == nil {
		artifact = string(b)
	}
	return compareRun{exit: exitCode, artifact: artifact, stderr: captured, err: err}
}

// A storage report with one finding, and an unread bucket the scan was denied.
func storageReport(t *testing.T, name string, findings, incomplete string) string {
	t.Helper()
	body := `{"findings":[` + findings + `],"total":1,"incomplete":[` + incomplete + `]}`
	return writeReport(t, name, body)
}

const publicBucketFinding = `{"Severity":"CRITICAL","Type":"PUBLIC_ACCESS","Provider":"aws","Bucket":"b","Detail":"public"}`

// The current run carries a DIFFERENT finding rather than none, so the
// baseline's is RESOLVED while the report is still classifiable. An empty
// findings array defeats compare.DetectType, which is a separate gap and would
// make these fixtures fail for a reason that is not the one they test.
const otherBucketFinding = `{"Severity":"HIGH","Type":"UNENCRYPTED","Provider":"aws","Bucket":"c","Detail":"unencrypted"}`

// The defect this wiring exists for: a finding the baseline saw and the current
// run could not read is RESOLVED by arithmetic. The record is what says the
// difference was not observed.
func TestRunCompare_CarriesBothInputsUnreadRecords(t *testing.T) {
	tests := []struct {
		name           string
		fromIncomplete string
		toIncomplete   string
		wantEntries    []string
	}{
		{
			name:           "the current run could not read part of the account",
			fromIncomplete: "",
			toIncomplete:   `"list buckets: AccessDenied"`,
			wantEntries:    []string{"current report: list buckets: AccessDenied"},
		},
		{
			name:           "the baseline could not either",
			fromIncomplete: `"describe regions: AccessDenied"`,
			toIncomplete:   "",
			wantEntries:    []string{"baseline report: describe regions: AccessDenied"},
		},
		{
			name:           "both sides, each labelled",
			fromIncomplete: `"baseline denied"`,
			toIncomplete:   `"current denied"`,
			wantEntries: []string{
				"baseline report: baseline denied",
				"current report: current denied",
			},
		},
		{
			// The positive control: a comparison over two whole scans must not
			// invent a record, or the assertions above pass on a constant.
			name:           "two whole scans report nothing unread",
			fromIncomplete: "",
			toIncomplete:   "",
			wantEntries:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			from := storageReport(t, "from.json", publicBucketFinding, tc.fromIncomplete)
			to := storageReport(t, "to.json", otherBucketFinding, tc.toIncomplete)

			got := runCompareWith(t, from, to, "json", "")
			if got.err != nil {
				t.Fatalf("unexpected error: %v", got.err)
			}

			var envelope struct {
				Incomplete []string `json:"incomplete"`
				Summary    struct {
					Resolved int `json:"resolved"`
				} `json:"summary"`
			}
			if err := json.Unmarshal([]byte(got.artifact), &envelope); err != nil {
				t.Fatalf("artifact is not JSON: %v (%s)", err, got.artifact)
			}

			if len(envelope.Incomplete) != len(tc.wantEntries) {
				t.Fatalf("incomplete = %v, want %v", envelope.Incomplete, tc.wantEntries)
			}
			for _, want := range tc.wantEntries {
				var found bool
				for _, entry := range envelope.Incomplete {
					if entry == want {
						found = true
					}
				}
				if !found {
					t.Errorf("the record does not carry %q: %v", want, envelope.Incomplete)
				}
			}

			// The finding is RESOLVED by arithmetic in every case here. That is
			// the number the record is next to, and why it matters.
			if envelope.Summary.Resolved != 1 {
				t.Errorf("resolved = %d, want 1 — this fixture must produce the case the record qualifies",
					envelope.Summary.Resolved)
			}
		})
	}
}

// The key is always present and empty rather than absent, for the same reason it
// is in every other envelope: an omitted key cannot be told from a tool that does
// not report its own coverage.
func TestRunCompare_TheEnvelopeAlwaysCarriesIncomplete(t *testing.T) {
	from := storageReport(t, "from.json", publicBucketFinding, "")
	to := storageReport(t, "to.json", publicBucketFinding, "")

	got := runCompareWith(t, from, to, "json", "")
	if got.err != nil {
		t.Fatalf("unexpected error: %v", got.err)
	}
	var envelope struct {
		Incomplete *[]string `json:"incomplete"`
	}
	if err := json.Unmarshal([]byte(got.artifact), &envelope); err != nil {
		t.Fatalf("artifact is not JSON: %v", err)
	}
	if envelope.Incomplete == nil {
		t.Fatalf("a comparison over two whole scans omitted the incomplete key or emitted null: %s", got.artifact)
	}
	if len(*envelope.Incomplete) != 0 {
		t.Errorf("a comparison over two whole scans reported %d incompletion(s)", len(*envelope.Incomplete))
	}
}

// The table is the artifact an operator keeps, and --output-file keeps only
// stdout.
func TestRunCompare_TheSavedTableCarriesItsOwnCoverage(t *testing.T) {
	t.Run("a partial input is named in the artifact", func(t *testing.T) {
		from := storageReport(t, "from.json", publicBucketFinding, "")
		to := storageReport(t, "to.json", otherBucketFinding, `"list buckets: AccessDenied"`)

		got := runCompareWith(t, from, to, "table", "")
		if got.err != nil {
			t.Fatalf("unexpected error: %v", got.err)
		}
		if !strings.Contains(got.artifact, "AccessDenied") {
			t.Errorf("the saved table does not name what the scan behind it could not read:\n%s", got.artifact)
		}
	})

	t.Run("whole inputs say so positively", func(t *testing.T) {
		from := storageReport(t, "from.json", publicBucketFinding, "")
		to := storageReport(t, "to.json", publicBucketFinding, "")

		got := runCompareWith(t, from, to, "table", "")
		if got.err != nil {
			t.Fatalf("unexpected error: %v", got.err)
		}
		if strings.Contains(got.artifact, "could not be completed") {
			t.Errorf("a comparison over two whole scans reported observations it could not complete:\n%s", got.artifact)
		}
	})
}

// The exit code is this command's contract with a merge gate. A comparison whose
// inputs were partial is not evidence that a finding was fixed.
func TestRunCompare_ExitCode(t *testing.T) {
	tests := []struct {
		name         string
		failOn       string
		toIncomplete string
		want         int
	}{
		{name: "informational run stays 0", failOn: "", toIncomplete: `"denied"`, want: 0},
		{name: "a partial input under --fail-on is 3", failOn: "LOW", toIncomplete: `"denied"`, want: 3},
		{name: "whole inputs under --fail-on stay 0", failOn: "LOW", toIncomplete: "", want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			from := storageReport(t, "from.json", publicBucketFinding, "")
			to := storageReport(t, "to.json", otherBucketFinding, tc.toIncomplete)

			got := runCompareWith(t, from, to, "json", tc.failOn)
			if got.err != nil {
				t.Fatalf("unexpected error: %v", got.err)
			}
			if got.exit != tc.want {
				t.Errorf("exit = %d, want %d", got.exit, tc.want)
			}
		})
	}
}

func TestRunCompare_RefusesInputItCannotUse(t *testing.T) {
	good := storageReport(t, "good.json", publicBucketFinding, "")

	t.Run("neither pair of flags", func(t *testing.T) {
		if got := runCompareWith(t, "", "", "json", ""); got.err == nil {
			t.Fatal("a run with no inputs was accepted")
		}
	})

	t.Run("a file that is not there", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.json")
		if got := runCompareWith(t, missing, good, "json", ""); got.err == nil {
			t.Fatal("a missing --from was accepted")
		}
		if got := runCompareWith(t, good, missing, "json", ""); got.err == nil {
			t.Fatal("a missing --to was accepted")
		}
	})

	t.Run("a report that cannot be normalized", func(t *testing.T) {
		bad := writeReport(t, "bad.json", `{"nothing":"recognisable"}`)
		if got := runCompareWith(t, bad, good, "json", ""); got.err == nil {
			t.Fatal("an unrecognisable --from was accepted")
		}
	})
}
