package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// A generated fix file outlives the run that produced it. It is reviewed later,
// in a pull request, by someone who never saw the command — so what the fix was
// built from has to be in the file, not on the terminal.
func TestProvenanceBanner(t *testing.T) {
	tests := []struct {
		name     string
		opts     Options
		wantNone bool
		wants    []string
		notWants []string
	}{
		{
			// A banner on every file is a warning that means nothing, and the one
			// that matters stops being read.
			name:     "a complete scan carries none",
			opts:     Options{Window: cloud.ScanWindow{RequestedDays: 90, ObservedDays: 90}},
			wantNone: true,
		},
		{
			name: "a narrowed window names both numbers and what bounded it",
			opts: Options{
				Incomplete: []string{"principal svc-billing: granted permissions: AccessDenied"},
				Window:     cloud.ScanWindow{RequestedDays: 365, ObservedDays: 90, LimitedBy: "aws"},
			},
			wants: []string{"PARTIAL SCAN", "svc-billing", "90 day(s)", "365", "aws"},
		},
		{
			// Unread observations with a window that was covered in full: the
			// scan looked back as far as it asked, and still could not see part
			// of the account.
			name: "a full window with unread observations",
			opts: Options{
				Incomplete: []string{"principal svc-etl: used permissions: AccessDenied"},
				Window:     cloud.ScanWindow{RequestedDays: 90, ObservedDays: 90},
			},
			wants:    []string{"PARTIAL SCAN", "svc-etl", "90 day(s)"},
			notWants: []string{"of the 90 requested"},
		},
		{
			// No window at all — a report predating the field. The caveat still
			// has to render, because the unread observations are the reason for
			// it and they are present.
			name:  "no window recorded",
			opts:  Options{Incomplete: []string{"list roles page: AccessDenied"}},
			wants: []string{"PARTIAL SCAN", "list roles page"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := provenanceBanner(tc.opts)
			if tc.wantNone {
				if got != "" {
					t.Fatalf("a complete scan produced a caveat:\n%s", got)
				}
				return
			}
			if got == "" {
				t.Fatal("a partial scan produced no caveat")
			}
			for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
				if line != "" && !strings.HasPrefix(line, "#") {
					t.Errorf("banner line %q is not a comment; it would change what a generated "+
						"file means", line)
				}
			}
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("banner does not carry %q:\n%s", want, got)
				}
			}
			for _, no := range tc.notWants {
				if strings.Contains(got, no) {
					t.Errorf("banner carries %q, which does not apply here:\n%s", no, got)
				}
			}
		})
	}
}

// An unread observation is a value read out of a saved report, so it reaches the
// banner as untrusted text. Rendered through CommentText, a newline in one cannot
// end its comment line and start something else in a file this tool writes.
func TestProvenanceBannerContainsAnEscapingObservation(t *testing.T) {
	got := provenanceBanner(Options{
		Incomplete: []string{"denied\nresource \"aws_iam_policy\" \"injected\" {}"},
	})
	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Fatalf("an observation left its comment line: %q", line)
		}
	}
}

// The caveat cannot go inside a raw IAM policy — that document has no comment
// syntax and anything added to it stops being a policy — so it is written beside
// them, and only when there is one to write.
func TestWriteRawPoliciesWritesThePartialScanNote(t *testing.T) {
	policies := map[string]cloud.Policy{
		"AIDA1": {Raw: []byte(`{"Version":"2012-10-17","Statement":[]}`)},
	}

	t.Run("partial scan", func(t *testing.T) {
		dir := t.TempDir()
		err := WriteRawPolicies(policies, Options{
			OutputDir:  dir,
			Incomplete: []string{"principal svc-billing: granted permissions: AccessDenied"},
			Window:     cloud.ScanWindow{RequestedDays: 365, ObservedDays: 90, LimitedBy: "aws"},
		})
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		note, err := os.ReadFile(filepath.Join(dir, partialScanNote))
		if err != nil {
			t.Fatalf("read the note: %v", err)
		}
		if !strings.Contains(string(note), "svc-billing") {
			t.Errorf("the note does not name what was unread:\n%s", note)
		}

		// The policies themselves are untouched: a reviewer applies them with a
		// tool that must still parse them.
		body, err := os.ReadFile(filepath.Join(dir, "aida1.json"))
		if err != nil {
			t.Fatalf("read the policy: %v", err)
		}
		if strings.Contains(string(body), "#") {
			t.Errorf("the caveat leaked into the policy document, which is no longer valid JSON:\n%s", body)
		}
	})

	t.Run("complete scan", func(t *testing.T) {
		dir := t.TempDir()
		if err := WriteRawPolicies(policies, Options{OutputDir: dir}); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, partialScanNote)); !os.IsNotExist(err) {
			t.Errorf("a complete scan wrote a partial-scan note (%v)", err)
		}
	})
}
