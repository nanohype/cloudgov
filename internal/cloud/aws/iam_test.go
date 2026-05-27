package aws

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// mockIAM implements iamAPI. Each method returns the canned response and
// error for its name. Multi-page paginators are supported by indexing into
// the pages slice keyed by the input's Marker.
type mockIAM struct {
	roles        [][]iamtypes.Role // each entry is a paginator page
	users        [][]iamtypes.User
	rolesErrAt   int // pagination call index that should return errRoles
	errRoles     error
	usersErrAt   int
	errUsers     error
	attachedRole map[string][][]iamtypes.AttachedPolicy // roleName -> pages
	attachedUser map[string][][]iamtypes.AttachedPolicy // userName -> pages
	inlineRole   map[string][][]string                  // roleName -> pages of policyNames
	inlineUser   map[string][][]string                  // userName -> pages of policyNames
	rolePolicy   map[string]map[string]string           // roleName -> policyName -> document
	userPolicy   map[string]map[string]string           // userName -> policyName -> document
	managed      map[string]string                      // policyArn -> document
	missingArns  map[string]bool                        // policyArn -> simulate NoSuchEntity on GetPolicy
	missingVers  map[string]bool                        // policyArn -> NoSuchEntity on GetPolicyVersion

	// call counters for pagination
	rolesCalls int
	usersCalls int
}

func (m *mockIAM) ListRoles(_ context.Context, in *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	idx := m.rolesCalls
	m.rolesCalls++
	if m.errRoles != nil && idx == m.rolesErrAt {
		return nil, m.errRoles
	}
	if idx >= len(m.roles) {
		return &iam.ListRolesOutput{}, nil
	}
	var marker *string
	if idx+1 < len(m.roles) {
		marker = awssdk.String("next")
	}
	return &iam.ListRolesOutput{
		Roles:       m.roles[idx],
		Marker:      marker,
		IsTruncated: marker != nil,
	}, nil
}

func (m *mockIAM) ListUsers(_ context.Context, in *iam.ListUsersInput, _ ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	idx := m.usersCalls
	m.usersCalls++
	if m.errUsers != nil && idx == m.usersErrAt {
		return nil, m.errUsers
	}
	if idx >= len(m.users) {
		return &iam.ListUsersOutput{}, nil
	}
	var marker *string
	if idx+1 < len(m.users) {
		marker = awssdk.String("next")
	}
	return &iam.ListUsersOutput{
		Users:       m.users[idx],
		Marker:      marker,
		IsTruncated: marker != nil,
	}, nil
}

func (m *mockIAM) ListAttachedRolePolicies(_ context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	pages := m.attachedRole[awssdk.ToString(in.RoleName)]
	if len(pages) == 0 {
		return &iam.ListAttachedRolePoliciesOutput{}, nil
	}
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: pages[0]}, nil
}

func (m *mockIAM) ListRolePolicies(_ context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	pages := m.inlineRole[awssdk.ToString(in.RoleName)]
	if len(pages) == 0 {
		return &iam.ListRolePoliciesOutput{}, nil
	}
	return &iam.ListRolePoliciesOutput{PolicyNames: pages[0]}, nil
}

func (m *mockIAM) GetRolePolicy(_ context.Context, in *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	doc, ok := m.rolePolicy[awssdk.ToString(in.RoleName)][awssdk.ToString(in.PolicyName)]
	if !ok {
		return nil, errors.New("not found")
	}
	return &iam.GetRolePolicyOutput{
		PolicyDocument: awssdk.String(doc),
	}, nil
}

func (m *mockIAM) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	pages := m.attachedUser[awssdk.ToString(in.UserName)]
	if len(pages) == 0 {
		return &iam.ListAttachedUserPoliciesOutput{}, nil
	}
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: pages[0]}, nil
}

func (m *mockIAM) ListUserPolicies(_ context.Context, in *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	pages := m.inlineUser[awssdk.ToString(in.UserName)]
	if len(pages) == 0 {
		return &iam.ListUserPoliciesOutput{}, nil
	}
	return &iam.ListUserPoliciesOutput{PolicyNames: pages[0]}, nil
}

func (m *mockIAM) GetUserPolicy(_ context.Context, in *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	doc, ok := m.userPolicy[awssdk.ToString(in.UserName)][awssdk.ToString(in.PolicyName)]
	if !ok {
		return nil, errors.New("not found")
	}
	return &iam.GetUserPolicyOutput{
		PolicyDocument: awssdk.String(doc),
	}, nil
}

func (m *mockIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	arn := awssdk.ToString(in.PolicyArn)
	if m.missingArns[arn] {
		return nil, &iamtypes.NoSuchEntityException{}
	}
	if _, ok := m.managed[arn]; !ok {
		return nil, errors.New("policy not found")
	}
	return &iam.GetPolicyOutput{
		Policy: &iamtypes.Policy{DefaultVersionId: awssdk.String("v1")},
	}, nil
}

// no-op to satisfy iamAPI. Quota tests use a dedicated mock that overrides this.
func (m *mockIAM) GetAccountSummary(_ context.Context, _ *iam.GetAccountSummaryInput, _ ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{}, nil
}

func (m *mockIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	arn := awssdk.ToString(in.PolicyArn)
	if m.missingVers[arn] {
		return nil, &iamtypes.NoSuchEntityException{}
	}
	doc, ok := m.managed[arn]
	if !ok {
		return nil, errors.New("version not found")
	}
	return &iam.GetPolicyVersionOutput{
		PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(doc)},
	}, nil
}

// ── ListPrincipals ────────────────────────────────────────────────────────────

func TestListPrincipals(t *testing.T) {
	tests := []struct {
		name   string
		mock   *mockIAM
		wantID []string
	}{
		{
			name: "roles and users from single page",
			mock: &mockIAM{
				roles: [][]iamtypes.Role{{
					{RoleId: awssdk.String("AROA1"), RoleName: awssdk.String("admin"), Description: awssdk.String("the boss")},
					{RoleId: awssdk.String("AROA2"), RoleName: awssdk.String("reader")},
				}},
				users: [][]iamtypes.User{{
					{UserId: awssdk.String("AIDA1"), UserName: awssdk.String("alice")},
				}},
			},
			wantID: []string{"AROA1", "AROA2", "AIDA1"},
		},
		{
			name: "multi-page roles accumulate across pages",
			mock: &mockIAM{
				roles: [][]iamtypes.Role{
					{{RoleId: awssdk.String("AROA1"), RoleName: awssdk.String("r1")}},
					{{RoleId: awssdk.String("AROA2"), RoleName: awssdk.String("r2")}},
				},
			},
			wantID: []string{"AROA1", "AROA2"},
		},
		{
			name: "role pagination error continues to users (warn-and-break)",
			mock: &mockIAM{
				errRoles:   errors.New("throttled"),
				rolesErrAt: 0,
				users: [][]iamtypes.User{{
					{UserId: awssdk.String("AIDA1"), UserName: awssdk.String("alice")},
				}},
			},
			wantID: []string{"AIDA1"},
		},
		{
			name: "user pagination error after partial role page still returns roles",
			mock: &mockIAM{
				roles: [][]iamtypes.Role{{
					{RoleId: awssdk.String("AROA1"), RoleName: awssdk.String("r1")},
				}},
				errUsers:   errors.New("throttled"),
				usersErrAt: 0,
			},
			wantID: []string{"AROA1"},
		},
		{
			name:   "empty account",
			mock:   &mockIAM{},
			wantID: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{iam: tt.mock}
			got, err := p.ListPrincipals(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotIDs := make([]string, len(got))
			for i, pr := range got {
				gotIDs[i] = pr.ID
			}
			if !equalStrings(gotIDs, tt.wantID) {
				t.Errorf("ids: got %v, want %v", gotIDs, tt.wantID)
			}
		})
	}
}

func TestListPrincipals_TypesAndMetadata(t *testing.T) {
	p := &Provider{iam: &mockIAM{
		roles: [][]iamtypes.Role{{
			{RoleId: awssdk.String("AROA1"), RoleName: awssdk.String("admin"), Description: awssdk.String("the boss")},
		}},
		users: [][]iamtypes.User{{
			{UserId: awssdk.String("AIDA1"), UserName: awssdk.String("alice")},
		}},
	}}
	got, err := p.ListPrincipals(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Type != cloud.PrincipalRole {
		t.Errorf("role principal type: got %v, want %v", got[0].Type, cloud.PrincipalRole)
	}
	if got[0].Metadata["description"] != "the boss" {
		t.Errorf("role description metadata: got %q", got[0].Metadata["description"])
	}
	if got[1].Type != cloud.PrincipalUser {
		t.Errorf("user principal type: got %v, want %v", got[1].Type, cloud.PrincipalUser)
	}
	if got[1].Provider != "aws" {
		t.Errorf("provider tag: got %q", got[1].Provider)
	}
}

// ── GrantedPermissions ────────────────────────────────────────────────────────

func TestGrantedPermissions_Role(t *testing.T) {
	tests := []struct {
		name      string
		principal cloud.Principal
		mock      *mockIAM
		wantPerms []cloud.Permission
	}{
		{
			name:      "role with managed policy",
			principal: cloud.Principal{Name: "admin", Type: cloud.PrincipalRole},
			mock: &mockIAM{
				attachedRole: map[string][][]iamtypes.AttachedPolicy{
					"admin": {{{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/ReadOnly")}}},
				},
				managed: map[string]string{
					"arn:aws:iam::aws:policy/ReadOnly": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
				},
			},
			wantPerms: []cloud.Permission{{Action: "s3:GetObject", Resource: "*"}},
		},
		{
			name:      "role with inline policy",
			principal: cloud.Principal{Name: "admin", Type: cloud.PrincipalRole},
			mock: &mockIAM{
				inlineRole: map[string][][]string{
					"admin": {{"inline-1"}},
				},
				rolePolicy: map[string]map[string]string{
					"admin": {
						"inline-1": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}`,
					},
				},
			},
			wantPerms: []cloud.Permission{{Action: "ec2:DescribeInstances", Resource: "*"}},
		},
		{
			name:      "role with URL-encoded inline policy document",
			principal: cloud.Principal{Name: "admin", Type: cloud.PrincipalRole},
			mock: &mockIAM{
				inlineRole: map[string][][]string{
					"admin": {{"inline-1"}},
				},
				rolePolicy: map[string]map[string]string{
					"admin": {
						"inline-1": url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::mybucket/*"}]}`),
					},
				},
			},
			wantPerms: []cloud.Permission{{Action: "s3:PutObject", Resource: "arn:aws:s3:::mybucket/*"}},
		},
		{
			name:      "role with action as array and resource as array — cross product",
			principal: cloud.Principal{Name: "admin", Type: cloud.PrincipalRole},
			mock: &mockIAM{
				attachedRole: map[string][][]iamtypes.AttachedPolicy{
					"admin": {{{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/Multi")}}},
				},
				managed: map[string]string{
					"arn:aws:iam::aws:policy/Multi": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::a/*","arn:aws:s3:::b/*"]}]}`,
				},
			},
			wantPerms: []cloud.Permission{
				{Action: "s3:GetObject", Resource: "arn:aws:s3:::a/*"},
				{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*"},
				{Action: "s3:PutObject", Resource: "arn:aws:s3:::a/*"},
				{Action: "s3:PutObject", Resource: "arn:aws:s3:::b/*"},
			},
		},
		{
			name:      "deny statements are ignored",
			principal: cloud.Principal{Name: "admin", Type: cloud.PrincipalRole},
			mock: &mockIAM{
				attachedRole: map[string][][]iamtypes.AttachedPolicy{
					"admin": {{{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/Mixed")}}},
				},
				managed: map[string]string{
					"arn:aws:iam::aws:policy/Mixed": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`,
				},
			},
			wantPerms: []cloud.Permission{{Action: "s3:GetObject", Resource: "*"}},
		},
		{
			name:      "missing managed policy (NoSuchEntity) is skipped, not fatal",
			principal: cloud.Principal{Name: "admin", Type: cloud.PrincipalRole},
			mock: &mockIAM{
				attachedRole: map[string][][]iamtypes.AttachedPolicy{
					"admin": {{
						{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/Gone")},
						{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/Good")},
					}},
				},
				missingArns: map[string]bool{"arn:aws:iam::aws:policy/Gone": true},
				managed: map[string]string{
					"arn:aws:iam::aws:policy/Good": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`,
				},
			},
			wantPerms: []cloud.Permission{{Action: "sts:AssumeRole", Resource: "*"}},
		},
		{
			name:      "missing policy version (NoSuchEntity) is skipped, not fatal",
			principal: cloud.Principal{Name: "admin", Type: cloud.PrincipalRole},
			mock: &mockIAM{
				attachedRole: map[string][][]iamtypes.AttachedPolicy{
					"admin": {{
						{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/Stale")},
					}},
				},
				missingVers: map[string]bool{"arn:aws:iam::aws:policy/Stale": true},
				managed: map[string]string{
					"arn:aws:iam::aws:policy/Stale": `{"Version":"2012-10-17","Statement":[]}`,
				},
			},
			wantPerms: nil,
		},
		{
			name:      "duplicate actions across attached and inline policies are deduped",
			principal: cloud.Principal{Name: "admin", Type: cloud.PrincipalRole},
			mock: &mockIAM{
				attachedRole: map[string][][]iamtypes.AttachedPolicy{
					"admin": {{{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/Same")}}},
				},
				inlineRole: map[string][][]string{
					"admin": {{"inline-1"}},
				},
				managed: map[string]string{
					"arn:aws:iam::aws:policy/Same": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
				},
				rolePolicy: map[string]map[string]string{
					"admin": {
						"inline-1": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
					},
				},
			},
			wantPerms: []cloud.Permission{{Action: "s3:GetObject", Resource: "*"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{iam: tt.mock}
			got, err := p.GrantedPermissions(context.Background(), tt.principal)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equalPerms(got, tt.wantPerms) {
				t.Errorf("perms: got %v, want %v", got, tt.wantPerms)
			}
		})
	}
}

func TestGrantedPermissions_User(t *testing.T) {
	mock := &mockIAM{
		attachedUser: map[string][][]iamtypes.AttachedPolicy{
			"alice": {{{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/ReadOnly")}}},
		},
		inlineUser: map[string][][]string{
			"alice": {{"inline-1"}},
		},
		managed: map[string]string{
			"arn:aws:iam::aws:policy/ReadOnly": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		},
		userPolicy: map[string]map[string]string{
			"alice": {
				"inline-1": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}`,
			},
		},
	}
	p := &Provider{iam: mock}
	got, err := p.GrantedPermissions(context.Background(), cloud.Principal{Name: "alice", Type: cloud.PrincipalUser})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []cloud.Permission{
		{Action: "s3:GetObject", Resource: "*"},
		{Action: "ec2:DescribeInstances", Resource: "*"},
	}
	if !equalPerms(got, want) {
		t.Errorf("perms: got %v, want %v", got, want)
	}
}

// ── MinimalPolicy ─────────────────────────────────────────────────────────────

func TestMinimalPolicy(t *testing.T) {
	tests := []struct {
		name        string
		used        []cloud.Permission
		wantActions []string // sorted, deduped across all statements
	}{
		{
			name:        "empty used permissions produces a policy with no statements",
			used:        nil,
			wantActions: nil,
		},
		{
			name:        "single permission",
			used:        []cloud.Permission{{Action: "s3:GetObject", Resource: "*"}},
			wantActions: []string{"s3:GetObject"},
		},
		{
			name: "duplicate actions on same resource are deduped",
			used: []cloud.Permission{
				{Action: "s3:GetObject", Resource: "*"},
				{Action: "s3:GetObject", Resource: "*"},
			},
			wantActions: []string{"s3:GetObject"},
		},
		{
			name: "missing resource defaults to wildcard",
			used: []cloud.Permission{
				{Action: "ec2:DescribeInstances", Resource: ""},
			},
			wantActions: []string{"ec2:DescribeInstances"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{}
			pol, err := p.MinimalPolicy(context.Background(), cloud.Principal{Name: "x"}, tt.used)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pol.Provider != "aws" || pol.Format != "aws-iam-json" {
				t.Errorf("policy header: got provider=%q format=%q", pol.Provider, pol.Format)
			}
			doc, err := parseDocument(string(pol.Raw))
			if err != nil {
				t.Fatalf("parse generated doc: %v", err)
			}
			var gotActions []string
			for _, s := range doc.Statement {
				gotActions = append(gotActions, toStringSlice(s.Action)...)
			}
			sort.Strings(gotActions)
			if !equalStrings(gotActions, tt.wantActions) {
				t.Errorf("actions: got %v, want %v", gotActions, tt.wantActions)
			}
		})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", ``, nil},
		{"single string", `"s3:GetObject"`, []string{"s3:GetObject"}},
		{"array", `["s3:GetObject","s3:PutObject"]`, []string{"s3:GetObject", "s3:PutObject"}},
		{"empty array", `[]`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toStringSlice([]byte(tt.raw))
			if !equalStrings(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDedupPermissions(t *testing.T) {
	in := []cloud.Permission{
		{Action: "s3:GetObject", Resource: "*"},
		{Action: "s3:GetObject", Resource: "*"},
		{Action: "s3:GetObject", Resource: "arn:aws:s3:::a/*"},
	}
	got := dedupPermissions(in)
	if len(got) != 2 {
		t.Fatalf("got %d perms, want 2: %v", len(got), got)
	}
}

func TestAccountIDFromPrincipal(t *testing.T) {
	tests := []struct {
		name string
		p    cloud.Principal
		want string
	}{
		{"role arn", cloud.Principal{Metadata: map[string]string{"arn": "arn:aws:iam::123456789012:role/admin"}}, "123456789012"},
		{"no arn metadata", cloud.Principal{Metadata: map[string]string{}}, ""},
		{"malformed arn", cloud.Principal{Metadata: map[string]string{"arn": "not-an-arn"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := accountIDFromPrincipal(tt.p)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ── test helpers ──────────────────────────────────────────────────────────────

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalPerms(a, b []cloud.Permission) bool {
	if len(a) != len(b) {
		return false
	}
	// order-insensitive comparison: GrantedPermissions composes from multiple
	// sources so callers shouldn't depend on order.
	matched := make([]bool, len(b))
	for _, x := range a {
		found := false
		for j, y := range b {
			if !matched[j] && x == y {
				matched[j] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
