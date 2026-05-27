package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/stxkxs/matlock/internal/cloud"
)

// roleAssignmentsAPI is the narrow RBAC role-assignments surface used here.
type roleAssignmentsAPI interface {
	ListForSubscription(ctx context.Context, filter string) ([]*armauthorization.RoleAssignment, error)
}

// roleDefinitionsAPI is the narrow RBAC role-definitions surface used here.
type roleDefinitionsAPI interface {
	GetByID(ctx context.Context, id string) (*armauthorization.RoleDefinition, error)
}

type roleAssignmentsAdapter struct {
	client *armauthorization.RoleAssignmentsClient
}

func (a *roleAssignmentsAdapter) ListForSubscription(ctx context.Context, filter string) ([]*armauthorization.RoleAssignment, error) {
	var opts *armauthorization.RoleAssignmentsClientListForSubscriptionOptions
	if filter != "" {
		opts = &armauthorization.RoleAssignmentsClientListForSubscriptionOptions{Filter: to.Ptr(filter)}
	}
	var out []*armauthorization.RoleAssignment
	pager := a.client.NewListForSubscriptionPager(opts)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

type roleDefinitionsAdapter struct {
	client *armauthorization.RoleDefinitionsClient
}

func (a *roleDefinitionsAdapter) GetByID(ctx context.Context, id string) (*armauthorization.RoleDefinition, error) {
	resp, err := a.client.GetByID(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &resp.RoleDefinition, nil
}

// ListPrincipals returns all unique principals from role assignments in the subscription.
func (p *Provider) ListPrincipals(ctx context.Context) ([]cloud.Principal, error) {
	assignments, err := p.roleAssignments.ListForSubscription(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list role assignments: %w", err)
	}

	seen := make(map[string]bool)
	var principals []cloud.Principal

	for _, ra := range assignments {
		if ra.Properties == nil || ra.Properties.PrincipalID == nil {
			continue
		}
		pid := *ra.Properties.PrincipalID
		if seen[pid] {
			continue
		}
		seen[pid] = true

		pt := principalType(ra.Properties.PrincipalType)
		name := pid
		if ra.Properties.PrincipalID != nil {
			name = *ra.Properties.PrincipalID
		}
		principals = append(principals, cloud.Principal{
			ID:       pid,
			Name:     name,
			Type:     pt,
			Provider: "azure",
			Metadata: map[string]string{
				"subscription": p.subscriptionID,
			},
		})
	}
	return principals, nil
}

func principalType(pt *armauthorization.PrincipalType) cloud.PrincipalType {
	if pt == nil {
		return cloud.PrincipalUser
	}
	switch *pt {
	case armauthorization.PrincipalTypeServicePrincipal:
		return cloud.PrincipalManagedIdentity
	default:
		return cloud.PrincipalUser
	}
}

// GrantedPermissions resolves all role definitions for the principal's assignments.
func (p *Provider) GrantedPermissions(ctx context.Context, principal cloud.Principal) ([]cloud.Permission, error) {
	filter := fmt.Sprintf("principalId eq '%s'", principal.ID)
	assignments, err := p.roleAssignments.ListForSubscription(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("list assignments for principal: %w", err)
	}

	var perms []cloud.Permission
	for _, ra := range assignments {
		if ra.Properties == nil || ra.Properties.RoleDefinitionID == nil {
			continue
		}
		scope := ""
		if ra.Properties.Scope != nil {
			scope = *ra.Properties.Scope
		}
		roleDefID := *ra.Properties.RoleDefinitionID
		roleDef, err := p.roleDefinitions.GetByID(ctx, roleDefID)
		if err != nil {
			continue
		}
		if roleDef.Properties == nil {
			continue
		}
		for _, perm := range roleDef.Properties.Permissions {
			for _, action := range perm.Actions {
				if action != nil {
					perms = append(perms, cloud.Permission{Action: *action, Resource: scope})
				}
			}
			for _, action := range perm.DataActions {
				if action != nil {
					perms = append(perms, cloud.Permission{Action: *action, Resource: scope})
				}
			}
		}
	}
	return perms, nil
}

// UsedPermissions queries Azure Activity Log for operations by the principal.
func (p *Provider) UsedPermissions(ctx context.Context, principal cloud.Principal, since time.Time) ([]cloud.Permission, error) {
	return p.activityLogPermissions(ctx, principal, since)
}

// MinimalPolicy builds an Azure custom role JSON from used permissions.
func (p *Provider) MinimalPolicy(_ context.Context, principal cloud.Principal, used []cloud.Permission) (cloud.Policy, error) {
	seen := make(map[string]bool)
	var actions []string
	for _, u := range used {
		if !seen[u.Action] {
			seen[u.Action] = true
			actions = append(actions, u.Action)
		}
	}

	type roleDefinition struct {
		Name             string   `json:"Name"`
		Description      string   `json:"Description"`
		Actions          []string `json:"Actions"`
		NotActions       []string `json:"NotActions"`
		AssignableScopes []string `json:"AssignableScopes"`
	}
	role := roleDefinition{
		Name:             "Minimal role for " + strings.ReplaceAll(principal.Name, "-", "_"),
		Description:      "Auto-generated by matlock — contains only observed permissions",
		Actions:          actions,
		NotActions:       []string{},
		AssignableScopes: []string{"/subscriptions/" + p.subscriptionID},
	}
	raw, err := json.MarshalIndent(role, "", "  ")
	if err != nil {
		return cloud.Policy{}, fmt.Errorf("marshal custom role: %w", err)
	}
	return cloud.Policy{
		Provider: "azure",
		Format:   "azure-custom-role",
		Raw:      raw,
	}, nil
}
