package gcp

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/api/cloudresourcemanager/v1"
	googleiam "google.golang.org/api/iam/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockCRM struct {
	policy *cloudresourcemanager.Policy
	err    error
}

func (m *mockCRM) GetIAMPolicy(_ context.Context, _ string) (*cloudresourcemanager.Policy, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.policy, nil
}

type mockGoogleIAM struct {
	roles map[string]*googleiam.Role
	err   error
}

func (m *mockGoogleIAM) GetRole(_ context.Context, name string) (*googleiam.Role, error) {
	if m.err != nil {
		return nil, m.err
	}
	if r, ok := m.roles[name]; ok {
		return r, nil
	}
	return nil, errors.New("role not found")
}

func TestListPrincipals(t *testing.T) {
	p := &Provider{
		projectID: "my-project",
		crm: &mockCRM{policy: &cloudresourcemanager.Policy{
			Bindings: []*cloudresourcemanager.Binding{
				{Role: "roles/owner", Members: []string{"user:alice@example.com", "serviceAccount:sa@my-project.iam.gserviceaccount.com"}},
				{Role: "roles/viewer", Members: []string{"user:alice@example.com"}}, // duplicate
				{Role: "roles/editor", Members: []string{"group:devs@example.com"}},
			},
		}},
	}
	got, err := p.ListPrincipals(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 unique principals (alice deduped), got %d: %v", len(got), got)
	}
	byID := map[string]cloud.PrincipalType{}
	for _, pr := range got {
		byID[pr.ID] = pr.Type
		if pr.Provider != "gcp" {
			t.Errorf("provider: got %q", pr.Provider)
		}
	}
	if byID["user:alice@example.com"] != cloud.PrincipalUser {
		t.Error("alice should be PrincipalUser")
	}
	if byID["serviceAccount:sa@my-project.iam.gserviceaccount.com"] != cloud.PrincipalServiceAccount {
		t.Error("service account should be PrincipalServiceAccount")
	}
}

func TestListPrincipals_Error(t *testing.T) {
	p := &Provider{crm: &mockCRM{err: errors.New("auth")}}
	_, err := p.ListPrincipals(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseMember(t *testing.T) {
	tests := []struct {
		member string
		wantPT cloud.PrincipalType
		wantN  string
	}{
		{"user:alice@example.com", cloud.PrincipalUser, "alice@example.com"},
		{"serviceAccount:sa@p.iam.gserviceaccount.com", cloud.PrincipalServiceAccount, "sa@p.iam.gserviceaccount.com"},
		{"group:devs@example.com", cloud.PrincipalUser, "devs@example.com"},
		{"allAuthenticatedUsers", cloud.PrincipalUser, "allAuthenticatedUsers"}, // no colon
		{"unknown:thing", cloud.PrincipalUser, "thing"},
	}
	for _, tt := range tests {
		t.Run(tt.member, func(t *testing.T) {
			pt, name := parseMember(tt.member)
			if pt != tt.wantPT || name != tt.wantN {
				t.Errorf("got (%v, %q), want (%v, %q)", pt, name, tt.wantPT, tt.wantN)
			}
		})
	}
}

func TestGrantedPermissions(t *testing.T) {
	p := &Provider{
		projectID: "my-project",
		crm: &mockCRM{policy: &cloudresourcemanager.Policy{
			Bindings: []*cloudresourcemanager.Binding{
				{Role: "roles/storage.admin", Members: []string{"user:alice@example.com"}},
				{Role: "roles/viewer", Members: []string{"user:bob@example.com"}},
			},
		}},
		googleIAM: &mockGoogleIAM{roles: map[string]*googleiam.Role{
			"roles/storage.admin": {IncludedPermissions: []string{"storage.buckets.list", "storage.buckets.get"}},
			"roles/viewer":        {IncludedPermissions: []string{"resourcemanager.projects.get"}},
		}},
	}
	got, err := p.GrantedPermissions(context.Background(),
		cloud.Principal{ID: "user:alice@example.com", Metadata: map[string]string{"member": "user:alice@example.com"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 perms for alice, got %d: %v", len(got), got)
	}
	for _, perm := range got {
		if perm.Resource != "projects/my-project" {
			t.Errorf("resource: got %q", perm.Resource)
		}
	}
}

func TestGrantedPermissions_RoleLookupFailureSkipped(t *testing.T) {
	p := &Provider{
		projectID: "p",
		crm: &mockCRM{policy: &cloudresourcemanager.Policy{
			Bindings: []*cloudresourcemanager.Binding{
				{Role: "roles/missing", Members: []string{"user:x"}},
				{Role: "roles/good", Members: []string{"user:x"}},
			},
		}},
		googleIAM: &mockGoogleIAM{roles: map[string]*googleiam.Role{
			"roles/good": {IncludedPermissions: []string{"valid.action"}},
		}},
	}
	got, _ := p.GrantedPermissions(context.Background(),
		cloud.Principal{ID: "user:x", Metadata: map[string]string{"member": "user:x"}})
	if len(got) != 1 || got[0].Action != "valid.action" {
		t.Errorf("expected one permission from the good role, got %v", got)
	}
}

func TestMinimalPolicy(t *testing.T) {
	p := &Provider{projectID: "p"}
	pol, err := p.MinimalPolicy(context.Background(),
		cloud.Principal{Name: "alice"},
		[]cloud.Permission{
			{Action: "storage.buckets.list"},
			{Action: "storage.buckets.list"}, // duplicate
			{Action: "storage.buckets.get"},
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol.Provider != "gcp" || pol.Format != "gcp-custom-role" {
		t.Errorf("header: provider=%q format=%q", pol.Provider, pol.Format)
	}
	if !contains(string(pol.Raw), "storage.buckets.list") {
		t.Error("expected list permission in policy")
	}
	if !contains(string(pol.Raw), "storage.buckets.get") {
		t.Error("expected get permission in policy")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
