package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockRoleAssignments struct {
	assignments []*armauthorization.RoleAssignment
	err         error
	lastFilter  string
}

func (m *mockRoleAssignments) ListForSubscription(_ context.Context, filter string) ([]*armauthorization.RoleAssignment, error) {
	m.lastFilter = filter
	return m.assignments, m.err
}

type mockRoleDefinitions struct {
	defs map[string]*armauthorization.RoleDefinition
	err  error
}

func (m *mockRoleDefinitions) GetByID(_ context.Context, id string) (*armauthorization.RoleDefinition, error) {
	if m.err != nil {
		return nil, m.err
	}
	if d, ok := m.defs[id]; ok {
		return d, nil
	}
	return nil, errors.New("not found")
}

func TestListPrincipals(t *testing.T) {
	p := &Provider{
		subscriptionID: "sub-1",
		roleAssignments: &mockRoleAssignments{assignments: []*armauthorization.RoleAssignment{
			{Properties: &armauthorization.RoleAssignmentProperties{PrincipalID: to.Ptr("user-1"),
				PrincipalType: to.Ptr(armauthorization.PrincipalTypeUser)}},
			{Properties: &armauthorization.RoleAssignmentProperties{PrincipalID: to.Ptr("user-1")}}, // dup
			{Properties: &armauthorization.RoleAssignmentProperties{PrincipalID: to.Ptr("sp-1"),
				PrincipalType: to.Ptr(armauthorization.PrincipalTypeServicePrincipal)}},
		}},
	}
	got, err := p.ListPrincipals(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 unique principals (user dedup), got %d", len(got))
	}
	if got[0].Provider != "azure" || got[0].Metadata["subscription"] != "sub-1" {
		t.Errorf("metadata: %+v", got[0])
	}
}

func TestListPrincipals_Error(t *testing.T) {
	p := &Provider{roleAssignments: &mockRoleAssignments{err: errors.New("auth")}}
	_, err := p.ListPrincipals(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPrincipalType(t *testing.T) {
	if principalType(nil) != cloud.PrincipalUser {
		t.Error("nil should map to User")
	}
	sp := armauthorization.PrincipalTypeServicePrincipal
	if principalType(&sp) != cloud.PrincipalManagedIdentity {
		t.Error("ServicePrincipal should map to ManagedIdentity")
	}
	user := armauthorization.PrincipalTypeUser
	if principalType(&user) != cloud.PrincipalUser {
		t.Error("User should map to User")
	}
}

func TestGrantedPermissions(t *testing.T) {
	mock := &mockRoleAssignments{assignments: []*armauthorization.RoleAssignment{
		{Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: to.Ptr("/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/reader"),
			Scope:            to.Ptr("/subscriptions/x"),
		}},
	}}
	defs := &mockRoleDefinitions{defs: map[string]*armauthorization.RoleDefinition{
		"/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/reader": {
			Properties: &armauthorization.RoleDefinitionProperties{
				Permissions: []*armauthorization.Permission{
					{Actions: []*string{to.Ptr("Microsoft.Storage/storageAccounts/read")}},
				},
			},
		},
	}}
	p := &Provider{
		subscriptionID:  "x",
		roleAssignments: mock,
		roleDefinitions: defs,
	}
	got, err := p.GrantedPermissions(context.Background(),
		cloud.Principal{ID: "user-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Action != "Microsoft.Storage/storageAccounts/read" {
		t.Errorf("got %v", got)
	}
	if mock.lastFilter == "" {
		t.Error("expected filter to be passed for principal ID")
	}
}

func TestGrantedPermissions_RoleLookupFailureSkipped(t *testing.T) {
	mock := &mockRoleAssignments{assignments: []*armauthorization.RoleAssignment{
		{Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: to.Ptr("missing"), Scope: to.Ptr("/scope"),
		}},
		{Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: to.Ptr("good"), Scope: to.Ptr("/scope"),
		}},
	}}
	defs := &mockRoleDefinitions{defs: map[string]*armauthorization.RoleDefinition{
		"good": {Properties: &armauthorization.RoleDefinitionProperties{
			Permissions: []*armauthorization.Permission{
				{Actions: []*string{to.Ptr("Microsoft.Compute/read")}},
			},
		}},
	}}
	p := &Provider{roleAssignments: mock, roleDefinitions: defs}
	got, _ := p.GrantedPermissions(context.Background(), cloud.Principal{ID: "x"})
	if len(got) != 1 {
		t.Errorf("expected 1 perm (missing role skipped), got %d: %v", len(got), got)
	}
}

func TestMinimalPolicy(t *testing.T) {
	p := &Provider{subscriptionID: "sub-1"}
	pol, err := p.MinimalPolicy(context.Background(),
		cloud.Principal{Name: "alice"},
		[]cloud.Permission{
			{Action: "Microsoft.Storage/read"},
			{Action: "Microsoft.Storage/read"}, // dup
			{Action: "Microsoft.Compute/read"},
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol.Provider != "azure" || pol.Format != "azure-custom-role" {
		t.Errorf("header: %+v", pol)
	}
	// Body should contain both unique actions
	body := string(pol.Raw)
	if !contains(body, "Microsoft.Storage/read") || !contains(body, "Microsoft.Compute/read") {
		t.Errorf("body missing expected actions: %s", body)
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
