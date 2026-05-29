package fix

import (
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
				`jsonencode({})`,
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
				`jsonencode({"Version":"2012-10-17","Statement":[]})`,
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
