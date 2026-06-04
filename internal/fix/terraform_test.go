package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestSlug(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "myuser", "myuser"},
		{"uppercase", "MyUser", "myuser"},
		{"slash", "path/to/role", "path_to_role"},
		{"at sign", "user@example.com", "user_at_example_com"},
		{"dot", "user.name", "user_name"},
		{"hyphen", "my-role", "my_role"},
		{"space", "my role", "my_role"},
		{"combined", "AWS/Service-Account.name@domain.com", "aws_service_account_name_at_domain_com"},
		{"already slug", "my_role_name", "my_role_name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := slug(tc.input)
			if got != tc.want {
				t.Errorf("slug(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestFormatAWSTF(t *testing.T) {
	tests := []struct {
		name          string
		s             string
		principalName string
		policy        cloud.Policy
		wantContains  []string
	}{
		{
			name:          "empty policy",
			s:             "my_user",
			principalName: "my_user",
			policy:        cloud.Policy{},
			wantContains: []string{
				`resource "aws_iam_policy" "minimal_my_user"`,
				`name        = "minimal-my-user"`,
				`policy      = <<POLICY`,
			},
		},
		{
			name:          "policy with raw JSON",
			s:             "dev_role",
			principalName: "dev_role",
			policy: cloud.Policy{
				Raw: []byte(`{"Version":"2012-10-17","Statement":[]}`),
			},
			wantContains: []string{
				`resource "aws_iam_policy" "minimal_dev_role"`,
				`name        = "minimal-dev-role"`,
				`policy      = <<POLICY`,
				`"Version": "2012-10-17"`,
			},
		},
		{
			name:          "principal name underscores replaced by hyphens in resource name",
			s:             "my_svc_role",
			principalName: "my_svc_role",
			policy:        cloud.Policy{},
			wantContains: []string{
				`name        = "minimal-my-svc-role"`,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatAWSTF(tc.s, tc.principalName, tc.policy)
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("formatAWSTF() output missing %q\nGot:\n%s", want, got)
				}
			}
		})
	}
}

func TestFormatAWSTF_NoJSONEncodeBug(t *testing.T) {
	out := formatAWSTF("dev_role", "dev_role", cloud.Policy{
		Raw: []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::b/*"}]}`),
	})
	if strings.Contains(out, "jsonencode(") {
		t.Errorf("output wraps raw JSON in jsonencode() — invalid HCL:\n%s", out)
	}
}

func TestFormatAWSTF_EscapesTemplateMarkers(t *testing.T) {
	out := formatAWSTF("r", "r", cloud.Policy{
		Raw: []byte(`{"Statement":[{"Resource":"arn:aws:s3:::b/${aws:username}/*"}]}`),
	})
	if !strings.Contains(out, "$${aws:username}") {
		t.Errorf("policy variable not escaped as $${aws:username}:\n%s", out)
	}
	// After removing the escaped markers, no bare ${ may remain — a leftover would
	// be interpolated by Terraform.
	if strings.Contains(strings.ReplaceAll(out, "$${", ""), "${") {
		t.Errorf("found an unescaped ${ in output:\n%s", out)
	}
}

// TestFormatAWSTF_ParsesAsHCL proves the generated file is valid HCL: `tofu fmt`
// parses (and would reformat) it and exits non-zero only on a syntax error.
// Skipped when tofu isn't installed (e.g. CI without OpenTofu).
func TestFormatAWSTF_ParsesAsHCL(t *testing.T) {
	tofu, err := exec.LookPath("tofu")
	if err != nil {
		t.Skip("tofu not in PATH; skipping HCL parse proof")
	}
	out := formatAWSTF("dev_role", "dev_role", cloud.Policy{
		// Includes the IAM policy variable ${aws:username}; without escaping, this
		// is exactly what made the generated HCL fail to parse.
		Raw: []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::b/${aws:username}/*"}]}`),
	})
	path := filepath.Join(t.TempDir(), "main.tf")
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command(tofu, "fmt", path).CombinedOutput(); err != nil {
		t.Fatalf("generated HCL does not parse under `tofu fmt`: %v\n%s\n---\n%s", err, b, out)
	}
}
