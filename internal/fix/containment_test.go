package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestNameComponentRefusesWhatCannotBeOneElement(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string // a fragment the refusal must carry, empty means accept
	}{
		{"plain provider", "aws", ""},
		{"dots inside a name", "eu-west-1.b", ""},
		{"leading dash", "-rf", ""}, // a prefix decides this; PathUnder judges the finished name
		{"empty", "", "is empty"},
		{"relative escape", "../ESCAPED", "path separator"},
		{"absolute path", "/etc/cron.d/x", "path separator"},
		{"separators that cancel", "a/../aws", "path separator"},
		{"backslash", `..\ESCAPED`, "path separator"},
		{"parent reference", "..", "directory reference"},
		{"current reference", ".", "directory reference"},
		// No separator in this one on purpose: with one, the separator branch
		// answers first and the case stops exercising what it names.
		{"newline", "aws\nrm", "not a letter, digit"},
		{"null byte", "aws\x00", "not a letter, digit"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NameComponent("provider", tc.value)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("NameComponent(%q) refused a usable value: %v", tc.value, err)
			case tc.want == "":
				return
			case err == nil:
				t.Fatalf("NameComponent(%q) accepted a value that cannot be one filename element", tc.value)
			case !strings.Contains(err.Error(), tc.want):
				t.Errorf("NameComponent(%q) refused for the wrong reason: got %q, want a message carrying %q",
					tc.value, err, tc.want)
			}
			// The refusal names the field and the value, so an operator holding a
			// report knows which entry to look at.
			if !strings.Contains(err.Error(), "provider") {
				t.Errorf("NameComponent(%q) refused without naming the field: %q", tc.value, err)
			}
		})
	}
}

func TestPathUnderKeepsTheWriteInsideTheDirectory(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		file string
		want string // the path it must produce, empty means refuse
		why  string // a fragment the refusal must carry
	}{
		{name: "plain name", dir: "out", file: "fix-aws.sh", want: "out/fix-aws.sh"},
		{name: "current directory", dir: ".", file: "fix-aws.sh", want: "fix-aws.sh"},
		{name: "trailing separator on dir", dir: "out/", file: "fix-aws.sh", want: "out/fix-aws.sh"},
		{name: "dots inside the name", dir: "out", file: "fix-a..b.sh", want: "out/fix-a..b.sh"},

		{name: "escapes one level", dir: "out", file: "../ESCAPED.sh", why: `".." segment`},
		{name: "escapes the working directory", dir: "out", file: "../../ESCAPED.sh", why: `".." segment`},
		// The property the whole check exists for: cancelling segments are refused
		// on the way in, not accepted because the arithmetic happens to come out
		// even. "x/../y.sh" resolves to out/y.sh, which is inside — and is still a
		// name this caller did not compose.
		{name: "segments that cancel back inside", dir: "out", file: "x/../fix-aws.sh", why: `".." segment`},
		{name: "reaches a subdirectory", dir: "out", file: "sub/fix-aws.sh", why: "does not land directly inside"},
		{name: "absolute", dir: "out", file: "/etc/cron.d/x", why: "does not land directly inside"},
		{name: "empty", dir: "out", file: "", why: "empty filename"},
		{name: "reads as a flag", dir: "out", file: "-rf.sh", why: "starts with a dash"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PathUnder(tc.dir, tc.file)
			if tc.want != "" {
				if err != nil {
					t.Fatalf("PathUnder(%q, %q) refused a contained write: %v", tc.dir, tc.file, err)
				}
				if got != filepath.Clean(tc.want) {
					t.Fatalf("PathUnder(%q, %q) = %q, want %q", tc.dir, tc.file, got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("PathUnder(%q, %q) = %q; it must refuse", tc.dir, tc.file, got)
			}
			if !strings.Contains(err.Error(), tc.why) {
				t.Errorf("PathUnder(%q, %q) refused for the wrong reason: got %q, want a message carrying %q",
					tc.dir, tc.file, err, tc.why)
			}
			if got != "" {
				t.Errorf("PathUnder(%q, %q) returned %q alongside a refusal; a caller that ignores the error would write there",
					tc.dir, tc.file, got)
			}
		})
	}
}

// The two layers are independent, and this is what says so. A name that
// NameComponent would refuse still cannot escape once it reaches PathUnder, so a
// generator written without the first check is contained by the second.
func TestPathUnderContainsWhatNameComponentWouldHaveCaught(t *testing.T) {
	for _, component := range []string{"../ESCAPED", "../../ESCAPED", "a/../aws", "/etc/passwd"} {
		if err := NameComponent("provider", component); err == nil {
			t.Fatalf("NameComponent accepted %q; this test needs a value the first layer refuses", component)
		}
		if got, err := PathUnder("out", "fix-"+component+".sh"); err == nil {
			t.Errorf("PathUnder let %q through as %q with no help from NameComponent", component, got)
		}
	}
}

// A principal with no name slugs to nothing, and a file named for nothing is a
// file the operator cannot connect to a finding. Both generators refuse it
// rather than writing "minimal_.tf" or ".json".
func TestGeneratorsRefuseAPrincipalThatNamesNothing(t *testing.T) {
	t.Run("terraform", func(t *testing.T) {
		dir := t.TempDir()
		err := writePrincipalTF(cloud.Principal{Provider: "aws"}, cloud.Policy{}, dir, "")
		if err == nil {
			t.Fatal("a principal with no name was accepted")
		}
		if !strings.Contains(err.Error(), "principal is empty") {
			t.Errorf("refusal did not name the field: %v", err)
		}
		assertEmpty(t, dir)
	})

	t.Run("raw policy", func(t *testing.T) {
		dir := t.TempDir()
		err := WriteRawPolicies(map[string]cloud.Policy{"": {Raw: []byte(`{}`)}}, Options{OutputDir: dir})
		if err == nil {
			t.Fatal("a policy with no principal id was accepted")
		}
		if !strings.Contains(err.Error(), "principal is empty") {
			t.Errorf("refusal did not name the field: %v", err)
		}
		assertEmpty(t, dir)
	})
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		t.Errorf("a refused write left %s behind in %s", e.Name(), dir)
	}
}

// The lexical answer is right and the file still lands outside dir when a
// symlink is already sitting at the name. The callers write with os.WriteFile,
// which follows one.
func TestPathUnderRefusesASymlinkAlreadyAtTheName(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	elsewhere := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "landed.sh"), filepath.Join(out, "fix-aws.sh")); err != nil {
		t.Skipf("this platform does not support symlinks: %v", err)
	}

	got, err := PathUnder(out, "fix-aws.sh")
	if err == nil {
		t.Fatalf("PathUnder returned %q for a name that is a symlink out of the directory", got)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the refusal does not say what it found: %v", err)
	}

	// The positive control: the same name with nothing at it is the ordinary
	// case and must pass, so the check above is not satisfied by refusing
	// everything.
	if _, err := PathUnder(out, "fix-gamma.sh"); err != nil {
		t.Errorf("a name with nothing at it was refused: %v", err)
	}
}

// The banner half of the containment. A newline in a report value ended the
// comment and started a line of its own in a file written 0700; these are the
// characters that can do that and the ones a terminal would act on while an
// operator reviewed the script.
func TestCommentTextKeepsAValueOnItsLine(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"ordinary text is untouched", "bucket is publicly readable", "bucket is publicly readable"},
		{"non-ascii is untouched", "région eu-ouest-1 — ouverte", "région eu-ouest-1 — ouverte"},
		{"newline", "unattached\naws s3 rb s3://victim --force", `unattached\naws s3 rb s3://victim --force`},
		{"carriage return", "a\rb", `a\rb`},
		{"tab", "a\tb", `a\tb`},
		{"bell", "a\ab", `a\x07b`},
		{"escape, which a terminal acts on", "a\x1b[2Kb", `a\x1b[2Kb`},
		{"delete", "a\x7fb", `a\x7fb`},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CommentText(tc.value)
			if got != tc.want {
				t.Errorf("CommentText(%q) = %q, want %q", tc.value, got, tc.want)
			}
			if strings.ContainsAny(got, "\n\r") {
				t.Errorf("CommentText(%q) = %q, which still ends its line", tc.value, got)
			}
		})
	}
}
