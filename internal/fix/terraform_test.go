package fix

import (
	"encoding/json"
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

func TestExtractGCPPermissions(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want []string
	}{
		{
			name: "nil raw",
			raw:  nil,
			want: nil,
		},
		{
			name: "empty raw",
			raw:  []byte(`{}`),
			want: nil,
		},
		{
			name: "single permission",
			raw: mustMarshal(t, map[string]interface{}{
				"includedPermissions": []string{"storage.objects.get"},
			}),
			want: []string{"storage.objects.get"},
		},
		{
			name: "multiple permissions",
			raw: mustMarshal(t, map[string]interface{}{
				"includedPermissions": []string{
					"storage.objects.get",
					"storage.objects.list",
					"bigquery.datasets.get",
				},
			}),
			want: []string{"storage.objects.get", "storage.objects.list", "bigquery.datasets.get"},
		},
		{
			name: "invalid JSON",
			raw:  []byte(`not-json`),
			want: nil,
		},
		{
			name: "no permissions field",
			raw: mustMarshal(t, map[string]interface{}{
				"name":  "projects/my-project/roles/myrole",
				"title": "My Role",
			}),
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractGCPPermissions(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("extractGCPPermissions() returned %d perms, want %d: got %v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("perm[%d] = %q, want %q", i, got[i], tc.want[i])
				}
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

func TestFormatGCPTF(t *testing.T) {
	tests := []struct {
		name          string
		s             string
		principalName string
		policy        cloud.Policy
		wantContains  []string
	}{
		{
			name:          "empty policy no permissions",
			s:             "my_sa",
			principalName: "my-sa@project.iam.gserviceaccount.com",
			policy:        cloud.Policy{},
			wantContains: []string{
				`resource "google_project_iam_custom_role" "minimal_my_sa"`,
				`role_id     = "minimal_my_sa"`,
				`title       = "Minimal role for my-sa@project.iam.gserviceaccount.com"`,
				`permissions = [`,
			},
		},
		{
			name:          "policy with permissions",
			s:             "dev_sa",
			principalName: "dev-sa@project.iam.gserviceaccount.com",
			policy: cloud.Policy{
				Raw: mustMarshal(t, map[string]interface{}{
					"includedPermissions": []string{
						"storage.objects.get",
						"bigquery.datasets.get",
					},
				}),
			},
			wantContains: []string{
				`resource "google_project_iam_custom_role" "minimal_dev_sa"`,
				`role_id     = "minimal_dev_sa"`,
				`"storage.objects.get"`,
				`"bigquery.datasets.get"`,
			},
		},
		{
			name:          "role_id uses slug",
			s:             "svc_at_domain_com",
			principalName: "svc@domain.com",
			policy:        cloud.Policy{},
			wantContains: []string{
				`role_id     = "minimal_svc_at_domain_com"`,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatGCPTF(tc.s, tc.principalName, tc.policy)
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("formatGCPTF() output missing %q\nGot:\n%s", want, got)
				}
			}
		})
	}
}

// mustMarshal marshals v to JSON or fails the test.
func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
