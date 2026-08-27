package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// GenerateTerraform is the entry point `iam fix` calls: it turns a scan's
// findings into remediation files on disk. Four of its decisions change what an
// operator is handed — which findings become a file, how many files one
// principal gets, what a non-AWS principal produces, and whether a failure to
// write reports as success — so each is pinned rather than left to the package
// average.

func awsFinding(id, name string, sev cloud.Severity) cloud.Finding {
	return cloud.Finding{
		Severity:  sev,
		Provider:  "aws",
		Principal: &cloud.Principal{ID: id, Name: name, Provider: "aws"},
	}
}

func tfNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestGenerateTerraform_WritesOneFilePerPrincipal(t *testing.T) {
	dir := t.TempDir()
	findings := []cloud.Finding{
		awsFinding("arn:role/admin", "admin-role", cloud.SeverityHigh),
		awsFinding("arn:role/reader", "reader-role", cloud.SeverityHigh),
	}
	policies := map[string]cloud.Policy{
		"arn:role/admin": {Raw: []byte(`{"Version":"2012-10-17","Statement":[]}`)},
	}

	if err := GenerateTerraform(findings, policies, Options{OutputDir: dir}); err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}

	if got := tfNames(t, dir); len(got) != 2 {
		t.Fatalf("wrote %v, want one file per principal", got)
	}

	body, err := os.ReadFile(filepath.Join(dir, "minimal_admin_role.tf"))
	if err != nil {
		t.Fatalf("read admin fix file: %v", err)
	}
	// The principal's policy has to reach the file it is named for. Emitting the
	// resource with an empty body would hand back a fix that revokes everything.
	for _, want := range []string{
		`resource "aws_iam_policy" "minimal_admin_role"`,
		`"Version": "2012-10-17"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("fix file missing %q\nGot:\n%s", want, body)
		}
	}
}

func TestGenerateTerraform_CreatesTheOutputDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "fixes")
	err := GenerateTerraform(
		[]cloud.Finding{awsFinding("arn:role/a", "a-role", cloud.SeverityHigh)},
		nil, Options{OutputDir: dir},
	)
	if err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "minimal_a_role.tf")); err != nil {
		t.Fatalf("expected the fix file under a created directory: %v", err)
	}
}

func TestGenerateTerraform_SkipsFindingsWithNoPrincipal(t *testing.T) {
	// `audit` mixes IAM findings with resource findings, whose Principal is nil.
	// Dereferencing one would panic the command that is meant to remediate it.
	dir := t.TempDir()
	findings := []cloud.Finding{
		{Severity: cloud.SeverityCritical, Provider: "aws", Resource: "bucket"},
		awsFinding("arn:role/a", "a-role", cloud.SeverityHigh),
	}

	if err := GenerateTerraform(findings, nil, Options{OutputDir: dir}); err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}

	got := tfNames(t, dir)
	if len(got) != 1 || got[0] != "minimal_a_role.tf" {
		t.Fatalf("wrote %v, want only the finding that carries a principal", got)
	}
}

func TestGenerateTerraform_HonoursTheSeverityFloor(t *testing.T) {
	// `--severity` is the operator's statement of what they intend to fix. A
	// finding below it must produce no file: a fix on disk reads as a decision
	// to apply it.
	dir := t.TempDir()
	findings := []cloud.Finding{
		awsFinding("arn:role/low", "low-role", cloud.SeverityLow),
		awsFinding("arn:role/crit", "crit-role", cloud.SeverityCritical),
	}

	err := GenerateTerraform(findings, nil, Options{OutputDir: dir, Severity: cloud.SeverityHigh})
	if err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}

	got := tfNames(t, dir)
	if len(got) != 1 || got[0] != "minimal_crit_role.tf" {
		t.Fatalf("wrote %v, want only the finding at or above the floor", got)
	}
}

func TestGenerateTerraform_SeverityFloorAdmitsTheFloorItself(t *testing.T) {
	// The comparison is `<`, so a finding exactly at the requested severity is
	// admitted. `--severity HIGH` silently dropping every HIGH would be the
	// off-by-one this pins against.
	dir := t.TempDir()
	err := GenerateTerraform(
		[]cloud.Finding{awsFinding("arn:role/h", "h-role", cloud.SeverityHigh)},
		nil, Options{OutputDir: dir, Severity: cloud.SeverityHigh},
	)
	if err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}
	if got := tfNames(t, dir); len(got) != 1 {
		t.Fatalf("wrote %v, want the finding at the floor to be admitted", got)
	}
}

func TestGenerateTerraform_OnePrincipalGetsOneFile(t *testing.T) {
	// A scan reports many findings against the same role. The remediation is one
	// minimal policy per principal, so repeated findings must collapse rather
	// than each rewrite the file.
	dir := t.TempDir()
	findings := []cloud.Finding{
		awsFinding("arn:role/a", "a-role", cloud.SeverityCritical),
		awsFinding("arn:role/a", "a-role", cloud.SeverityHigh),
		awsFinding("arn:role/a", "a-role", cloud.SeverityMedium),
	}

	if err := GenerateTerraform(findings, nil, Options{OutputDir: dir}); err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}
	if got := tfNames(t, dir); len(got) != 1 {
		t.Fatalf("wrote %v, want one file for one principal", got)
	}
}

func TestGenerateTerraform_NonAWSPrincipalGetsNoTerraform(t *testing.T) {
	// No template exists for other providers. The file has to say so: emitting
	// an empty or AWS-shaped resource would be a fix that cannot apply.
	dir := t.TempDir()
	findings := []cloud.Finding{{
		Severity:  cloud.SeverityHigh,
		Provider:  "gcp",
		Principal: &cloud.Principal{ID: "sa/one", Name: "svc-account", Provider: "gcp"},
	}}

	if err := GenerateTerraform(findings, nil, Options{OutputDir: dir}); err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "minimal_svc_account.tf"))
	if err != nil {
		t.Fatalf("read fix file: %v", err)
	}
	if !strings.Contains(string(body), `no Terraform template available for provider "gcp"`) {
		t.Errorf("unsupported provider did not produce a placeholder:\n%s", body)
	}
	if strings.Contains(string(body), "aws_iam_policy") {
		t.Errorf("unsupported provider produced an AWS resource:\n%s", body)
	}
}

func TestGenerateTerraform_EmptyFindingsIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateTerraform(nil, nil, Options{OutputDir: dir}); err != nil {
		t.Fatalf("a clean scan should produce no files and no error, got %v", err)
	}
	if got := tfNames(t, dir); len(got) != 0 {
		t.Fatalf("wrote %v for an empty finding set", got)
	}
}

func TestGenerateTerraform_ReportsAnUnusableDirectory(t *testing.T) {
	// `iam fix` treats a nil error as "the fix files are on disk".
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	err := GenerateTerraform(
		[]cloud.Finding{awsFinding("arn:role/a", "a-role", cloud.SeverityHigh)},
		nil, Options{OutputDir: file},
	)
	if err == nil {
		t.Fatal("writing into a non-directory reported success")
	}
	if !strings.Contains(err.Error(), "create output dir") {
		t.Errorf("error did not name the failing step: %v", err)
	}
}

func TestGenerateTerraform_ReportsAFileItCouldNotWrite(t *testing.T) {
	// A fix file that could not be written must not report as generated, and the
	// error has to name the principal — the operator's next move is to re-run
	// for that role, which an unnamed `is a directory` does not tell them.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "minimal_a_role.tf"), 0o750); err != nil {
		t.Fatalf("setup: %v", err)
	}

	err := GenerateTerraform(
		[]cloud.Finding{awsFinding("arn:role/a", "a-role", cloud.SeverityHigh)},
		nil, Options{OutputDir: dir},
	)
	if err == nil {
		t.Fatal("an unwritable fix file reported success")
	}
	if !strings.Contains(err.Error(), "a-role") {
		t.Errorf("error did not name the principal it failed for: %v", err)
	}
}

func TestGenerateTerraform_WritesRestrictiveModes(t *testing.T) {
	// A generated fix names the permissions a principal is about to be reduced
	// to. 0600 on the files and 0750 on the directory keep a shared or CI
	// checkout from exposing them.
	dir := filepath.Join(t.TempDir(), "fixes")
	err := GenerateTerraform(
		[]cloud.Finding{awsFinding("arn:role/a", "a-role", cloud.SeverityHigh)},
		nil, Options{OutputDir: dir},
	)
	if err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("output directory is world-accessible: %v", perm)
	}

	fi, err := os.Stat(filepath.Join(dir, "minimal_a_role.tf"))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("fix file mode = %v, want 0600", perm)
	}
}

func TestGenerateTerraform_PrincipalNameStaysInsideTheOutputDirectory(t *testing.T) {
	// Principal names come from the API, not the operator. The slug replaces the
	// separator and the dot, so no name can walk out of the directory it was
	// handed.
	root := t.TempDir()
	dir := filepath.Join(root, "out")

	err := GenerateTerraform([]cloud.Finding{
		awsFinding("arn:role/escape", "../../escaped", cloud.SeverityHigh),
		awsFinding("arn:role/nested", "platform/admin", cloud.SeverityHigh),
	}, nil, Options{OutputDir: dir})
	if err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}

	outside, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir root: %v", err)
	}
	if len(outside) != 1 || outside[0].Name() != "out" {
		t.Fatalf("wrote outside the output directory: %v", outside)
	}
	for _, name := range tfNames(t, dir) {
		if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			t.Errorf("filename %q is not a plain leaf name", name)
		}
	}
}

func TestFormatAWSTF_UnindentableJSONIsEmittedVerbatim(t *testing.T) {
	// The policy body is whatever the API returned. When it will not parse as
	// JSON the raw bytes still have to reach the file: dropping to "{}" would
	// hand back a fix that revokes every permission the principal holds.
	raw := []byte(`{"Version":"2012-10-17",`)
	out := formatAWSTF("broken_role", "broken-role", cloud.Policy{Raw: raw})

	if !strings.Contains(out, string(raw)) {
		t.Errorf("malformed policy body was not emitted verbatim:\n%s", out)
	}
	if strings.Contains(out, "POLICY\n{}\nPOLICY") {
		t.Errorf("malformed policy body collapsed to an empty document:\n%s", out)
	}
}
