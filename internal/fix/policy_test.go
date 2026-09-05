package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// WriteRawPolicies takes a filename from a principal ID that came out of an AWS
// API, and writes IAM policy documents with it. Two properties are worth pinning
// beyond "it wrote the file": the output stays inside the directory it was given
// no matter what the principal ID looks like, and the mode is restrictive —
// these are the account's authorization documents landing on someone's disk.

func TestWriteRawPolicies_WritesOnePerPrincipal(t *testing.T) {
	dir := t.TempDir()
	policies := map[string]cloud.Policy{
		"admin-role":  {Raw: []byte(`{"Version":"2012-10-17"}`)},
		"reader-role": {Raw: []byte(`{"Version":"2012-10-17","Statement":[]}`)},
	}

	if err := WriteRawPolicies(policies, Options{OutputDir: dir}); err != nil {
		t.Fatalf("WriteRawPolicies: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("wrote %d files, want 2", len(entries))
	}

	got, err := os.ReadFile(filepath.Join(dir, "admin_role.json"))
	if err != nil {
		t.Fatalf("read admin policy: %v", err)
	}
	if string(got) != `{"Version":"2012-10-17"}` {
		t.Errorf("policy body round-tripped as %q", got)
	}
}

func TestWriteRawPolicies_CreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "policies")
	if err := WriteRawPolicies(map[string]cloud.Policy{
		"role": {Raw: []byte("{}")},
	}, Options{OutputDir: dir}); err != nil {
		t.Fatalf("WriteRawPolicies: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "role.json")); err != nil {
		t.Fatalf("expected the policy under a created directory: %v", err)
	}
}

func TestWriteRawPolicies_SkipsPrincipalsWithNoDocument(t *testing.T) {
	// A principal whose policy could not be read has an empty Raw. Writing an
	// empty file for it would put a document on disk that says the principal
	// grants nothing, which is the opposite of "we could not read it".
	dir := t.TempDir()
	if err := WriteRawPolicies(map[string]cloud.Policy{
		"unreadable": {},
		"readable":   {Raw: []byte("{}")},
	}, Options{OutputDir: dir}); err != nil {
		t.Fatalf("WriteRawPolicies: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "readable.json" {
		t.Fatalf("wrote %v, want only readable.json", entries)
	}
}

func TestWriteRawPolicies_StaysInsideTheOutputDirectory(t *testing.T) {
	// Principal IDs are ARNs and come from the API, not from the operator. The
	// slug replaces both the separator and the dot, so no id can walk out of
	// the directory it was handed — this pins that, because the guard lives in
	// a general-purpose helper that a later simplification could relax.
	root := t.TempDir()
	dir := filepath.Join(root, "out")

	if err := WriteRawPolicies(map[string]cloud.Policy{
		"../../escaped": {Raw: []byte("{}")},
		"arn:aws:iam::111111111111:role/platform/admin": {Raw: []byte("{}")},
	}, Options{OutputDir: dir}); err != nil {
		t.Fatalf("WriteRawPolicies: %v", err)
	}

	// Nothing above the output directory.
	outside, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir root: %v", err)
	}
	if len(outside) != 1 || outside[0].Name() != "out" {
		t.Fatalf("wrote outside the output directory: %v", outside)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir out: %v", err)
	}
	for _, e := range entries {
		if strings.ContainsAny(e.Name(), `/\`) || strings.Contains(e.Name(), "..") {
			t.Errorf("filename %q is not a plain leaf name", e.Name())
		}
	}
	if len(entries) != 2 {
		t.Fatalf("wrote %d files, want 2", len(entries))
	}
}

func TestWriteRawPolicies_WritesRestrictiveModes(t *testing.T) {
	// These are the account's authorization documents. 0600 on the files and
	// 0750 on the directory keep a shared or CI checkout from exposing them.
	dir := filepath.Join(t.TempDir(), "policies")
	if err := WriteRawPolicies(map[string]cloud.Policy{
		"role": {Raw: []byte("{}")},
	}, Options{OutputDir: dir}); err != nil {
		t.Fatalf("WriteRawPolicies: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("output directory is world-accessible: %v", perm)
	}

	fi, err := os.Stat(filepath.Join(dir, "role.json"))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("policy file mode = %v, want 0600", perm)
	}
}

func TestWriteRawPolicies_ReportsAnUnusableDirectory(t *testing.T) {
	// A path that cannot become a directory has to fail loudly: `remediate`
	// callers treat a nil error as "the policies are on disk".
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	err := WriteRawPolicies(map[string]cloud.Policy{"role": {Raw: []byte("{}")}}, Options{OutputDir: file})
	if err == nil {
		t.Fatal("writing into a non-directory reported success")
	}
	if !strings.Contains(err.Error(), "create output dir") {
		t.Errorf("error did not name the failing step: %v", err)
	}
}

func TestWriteRawPolicies_EmptyInputIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := WriteRawPolicies(map[string]cloud.Policy{}, Options{OutputDir: dir}); err != nil {
		t.Fatalf("empty policy set should be a no-op, got %v", err)
	}
}
