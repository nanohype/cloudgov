package iam

import (
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// helpers

func makePrincipal(id, name, provider string, meta map[string]string) cloud.Principal {
	return cloud.Principal{
		ID:       id,
		Name:     name,
		Type:     cloud.PrincipalUser,
		Provider: provider,
		Metadata: meta,
	}
}

func perm(action, resource string) cloud.Permission {
	return cloud.Permission{Action: action, Resource: resource}
}

func containsType(findings []cloud.Finding, ft cloud.FindingType) bool {
	for _, f := range findings {
		if f.Type == ft {
			return true
		}
	}
	return false
}

func countType(findings []cloud.Finding, ft cloud.FindingType) int {
	n := 0
	for _, f := range findings {
		if f.Type == ft {
			n++
		}
	}
	return n
}

func TestAnalyze_AdminAction(t *testing.T) {
	p := makePrincipal("u1", "admin-user", "aws", nil)

	tests := []struct {
		action string
	}{
		{"*"},
		{"s3:*"},
		{"iam:*"},
		{"ec2:*"},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			granted := []cloud.Permission{perm(tc.action, "arn:aws:s3:::bucket")}
			findings := analyze(p, granted, nil, 30)
			if !containsType(findings, cloud.FindingAdminAccess) {
				t.Errorf("action %q: expected FindingAdminAccess", tc.action)
			}
			for _, f := range findings {
				if f.Type == cloud.FindingAdminAccess && f.Severity != cloud.SeverityCritical {
					t.Errorf("admin access severity: want CRITICAL, got %s", f.Severity)
				}
			}
		})
	}
}

func TestAnalyze_AdminSkipsOtherChecks(t *testing.T) {
	meta := map[string]string{"account_id": "111111111111"}
	p := makePrincipal("u1", "admin-role", "aws", meta)
	granted := []cloud.Permission{perm("*", "arn:aws:s3:us-east-1:999999999999:bucket")}
	findings := analyze(p, granted, nil, 30)

	if containsType(findings, cloud.FindingWildcardResource) {
		t.Error("admin action should not also produce WildcardResource finding")
	}
	if containsType(findings, cloud.FindingCrossAccountAccess) {
		t.Error("admin action should not also produce CrossAccountAccess finding")
	}
	if containsType(findings, cloud.FindingUnusedPermission) {
		t.Error("admin action should not also produce UnusedPermission finding")
	}
}

func TestAnalyze_WildcardResource(t *testing.T) {
	p := makePrincipal("u1", "test-user", "aws", nil)
	granted := []cloud.Permission{perm("s3:GetObject", "*")}
	used := []cloud.Permission{perm("s3:GetObject", "*")}
	findings := analyze(p, granted, used, 30)

	if !containsType(findings, cloud.FindingWildcardResource) {
		t.Errorf("expected FindingWildcardResource, got %v", findings)
	}
	for _, f := range findings {
		if f.Type == cloud.FindingWildcardResource && f.Severity != cloud.SeverityCritical {
			t.Errorf("wildcard resource severity: want CRITICAL, got %s", f.Severity)
		}
	}
	if containsType(findings, cloud.FindingAdminAccess) {
		t.Error("non-admin action on wildcard resource should not produce FindingAdminAccess")
	}
}

func TestAnalyze_UnusedPermission(t *testing.T) {
	p := makePrincipal("u1", "test-user", "aws", nil)
	granted := []cloud.Permission{
		perm("s3:GetObject", "arn:aws:s3:::bucket/*"),
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
	}
	used := []cloud.Permission{perm("s3:GetObject", "arn:aws:s3:::bucket/*")}
	findings := analyze(p, granted, used, 30)

	if !containsType(findings, cloud.FindingUnusedPermission) {
		t.Errorf("expected FindingUnusedPermission, got %v", findings)
	}
	for _, f := range findings {
		if f.Type == cloud.FindingUnusedPermission {
			if strings.Contains(f.Detail, "s3:GetObject") {
				t.Error("s3:GetObject was used and must not be marked unused")
			}
			if !strings.Contains(f.Detail, "s3:PutObject") {
				t.Errorf("unused detail should mention s3:PutObject, got: %s", f.Detail)
			}
			if f.Severity != cloud.SeverityHigh {
				t.Errorf("unused permission severity: want HIGH, got %s", f.Severity)
			}
		}
	}
}

func TestAnalyze_NoUnusedWhenUsedIsEmpty(t *testing.T) {
	p := makePrincipal("u1", "idle-user", "aws", nil)
	granted := []cloud.Permission{perm("s3:GetObject", "arn:aws:s3:::bucket/*")}
	findings := analyze(p, granted, nil, 30)

	if containsType(findings, cloud.FindingUnusedPermission) {
		t.Error("should not emit UnusedPermission when used list is empty")
	}
	if !containsType(findings, cloud.FindingStalePrincipal) {
		t.Error("expected FindingStalePrincipal for principal with no activity")
	}
}

func TestAnalyze_UsedWildcardMatchesSpecificGrant(t *testing.T) {
	p := makePrincipal("u1", "test-user", "aws", nil)
	granted := []cloud.Permission{perm("s3:GetObject", "arn:aws:s3:::bucket/*")}
	used := []cloud.Permission{perm("s3:GetObject", "*")}
	findings := analyze(p, granted, used, 30)

	if containsType(findings, cloud.FindingUnusedPermission) {
		t.Error("wildcard usage should satisfy specific resource grant check")
	}
}

func TestAnalyze_StalePrincipal(t *testing.T) {
	p := makePrincipal("u1", "stale-role", "aws", nil)
	granted := []cloud.Permission{perm("ec2:DescribeInstances", "arn:aws:ec2:us-east-1:*:instance/*")}
	findings := analyze(p, granted, []cloud.Permission{}, 90)

	if !containsType(findings, cloud.FindingStalePrincipal) {
		t.Errorf("expected FindingStalePrincipal, got %v", findings)
	}
	for _, f := range findings {
		if f.Type == cloud.FindingStalePrincipal {
			if f.Severity != cloud.SeverityMedium {
				t.Errorf("stale principal severity: want MEDIUM, got %s", f.Severity)
			}
			if !strings.Contains(f.Detail, "90") {
				t.Errorf("stale principal detail should mention days=90, got: %s", f.Detail)
			}
		}
	}
}

func TestAnalyze_NoStalePrincipalWhenGrantedEmpty(t *testing.T) {
	p := makePrincipal("u1", "empty-user", "aws", nil)
	findings := analyze(p, []cloud.Permission{}, []cloud.Permission{}, 30)
	if len(findings) != 0 {
		t.Errorf("expected no findings for principal with no grants, got %v", findings)
	}
}

func TestAnalyze_CrossAccountAccess(t *testing.T) {
	meta := map[string]string{"account_id": "111111111111"}
	p := makePrincipal("u1", "cross-account-role", "aws", meta)

	tests := []struct {
		name     string
		resource string
		wantFlag bool
	}{
		{"same account", "arn:aws:s3:us-east-1:111111111111:bucket", false},
		{"different account", "arn:aws:s3:us-east-1:222222222222:bucket", true},
		{"wildcard account", "arn:aws:s3:us-east-1:*:bucket", false},
		{"no account in ARN", "arn:aws:s3:::bucket", false},
		{"non-aws resource", "projects/myproject/topics/mytopic", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			granted := []cloud.Permission{perm("s3:GetObject", tc.resource)}
			used := []cloud.Permission{perm("s3:GetObject", tc.resource)}
			findings := analyze(p, granted, used, 30)
			got := containsType(findings, cloud.FindingCrossAccountAccess)
			if got != tc.wantFlag {
				t.Errorf("resource %q: cross-account flag = %v, want %v", tc.resource, got, tc.wantFlag)
			}
		})
	}
}

func TestAnalyze_CrossAccountRequiresAccountID(t *testing.T) {
	p := makePrincipal("u1", "no-meta-user", "aws", nil)
	granted := []cloud.Permission{perm("s3:GetObject", "arn:aws:s3:us-east-1:999999999999:bucket")}
	used := []cloud.Permission{perm("s3:GetObject", "arn:aws:s3:us-east-1:999999999999:bucket")}
	findings := analyze(p, granted, used, 30)
	if containsType(findings, cloud.FindingCrossAccountAccess) {
		t.Error("cross-account check requires account_id metadata; should not flag without it")
	}
}

func TestAnalyze_Dedup(t *testing.T) {
	p := makePrincipal("u1", "test-user", "aws", nil)
	granted := []cloud.Permission{
		perm("s3:GetObject", "*"),
		perm("s3:GetObject", "*"),
	}
	used := []cloud.Permission{perm("s3:GetObject", "*")}
	findings := analyze(p, granted, used, 30)

	if n := countType(findings, cloud.FindingWildcardResource); n != 1 {
		t.Errorf("expected 1 WildcardResource finding after dedup, got %d", n)
	}
}

func TestAnalyze_MultipleFindings(t *testing.T) {
	meta := map[string]string{"account_id": "111111111111"}
	p := makePrincipal("u1", "over-privileged", "aws", meta)
	granted := []cloud.Permission{
		perm("s3:GetObject", "*"),
		perm("s3:PutObject", "arn:aws:s3:::bucket/*"),
		perm("s3:DeleteObject", "arn:aws:s3:us-east-1:222222222222:bucket"),
	}
	used := []cloud.Permission{perm("s3:GetObject", "*")}
	findings := analyze(p, granted, used, 30)

	for _, wantType := range []cloud.FindingType{
		cloud.FindingWildcardResource,
		cloud.FindingUnusedPermission,
		cloud.FindingCrossAccountAccess,
	} {
		if !containsType(findings, wantType) {
			t.Errorf("expected finding type %s", wantType)
		}
	}
}

func TestIsAdminAction(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{"*", true},
		{"s3:*", true},
		{"iam:*", true},
		{"ec2:*", true},
		{"s3:GetObject", false},
		{"ec2:DescribeInstances", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			if got := isAdminAction(tc.action); got != tc.want {
				t.Errorf("isAdminAction(%q) = %v, want %v", tc.action, got, tc.want)
			}
		})
	}
}

func TestIsWildcardResource(t *testing.T) {
	tests := []struct {
		resource string
		want     bool
	}{
		{"*", true},
		{"arn:aws:s3:::bucket/*", false},
		{"", false},
		{"projects/*/topics/*", false},
	}
	for _, tc := range tests {
		t.Run(tc.resource, func(t *testing.T) {
			if got := isWildcardResource(tc.resource); got != tc.want {
				t.Errorf("isWildcardResource(%q) = %v, want %v", tc.resource, got, tc.want)
			}
		})
	}
}

func TestIsCrossAccount(t *testing.T) {
	tests := []struct {
		accountID string
		resource  string
		want      bool
	}{
		{"123456789012", "arn:aws:s3:us-east-1:999999999999:bucket", true},
		{"123456789012", "arn:aws:s3:us-east-1:123456789012:bucket", false},
		{"123456789012", "arn:aws:s3:::bucket", false},
		{"123456789012", "arn:aws:s3:us-east-1:*:bucket", false},
		{"123456789012", "not-an-arn", false},
		{"123456789012", "projects/myproject", false},
		{"123456789012", "arn:aws:s3:us", false},
	}
	for _, tc := range tests {
		t.Run(tc.resource, func(t *testing.T) {
			if got := isCrossAccount(tc.accountID, tc.resource); got != tc.want {
				t.Errorf("isCrossAccount(%q, %q) = %v, want %v", tc.accountID, tc.resource, got, tc.want)
			}
		})
	}
}

func TestNormalizeKey(t *testing.T) {
	tests := []struct {
		action, resource, want string
	}{
		{"s3:GetObject", "arn:aws:s3:::bucket/*", "s3:getobject|arn:aws:s3:::bucket/*"},
		{"S3:GETOBJECT", "arn:aws:s3:::bucket/*", "s3:getobject|arn:aws:s3:::bucket/*"},
		{"*", "*", "*|*"},
		{"s3:GetObject", "*", "s3:getobject|*"},
	}
	for _, tc := range tests {
		t.Run(tc.action+"|"+tc.resource, func(t *testing.T) {
			if got := normalizeKey(tc.action, tc.resource); got != tc.want {
				t.Errorf("normalizeKey(%q, %q) = %q, want %q", tc.action, tc.resource, got, tc.want)
			}
		})
	}
}

func TestDedupFindings(t *testing.T) {
	p := cloud.Principal{ID: "u1", Name: "user"}
	findings := []cloud.Finding{
		{Type: cloud.FindingWildcardResource, Resource: "*", Principal: &p},
		{Type: cloud.FindingWildcardResource, Resource: "*", Principal: &p},
		{Type: cloud.FindingUnusedPermission, Resource: "arn:aws:s3:::bucket", Principal: &p},
	}
	deduped := dedupFindings(findings)
	if len(deduped) != 2 {
		t.Errorf("expected 2 unique findings after dedup, got %d", len(deduped))
	}
}

func TestDedupFindings_DifferentPrincipals(t *testing.T) {
	p1 := cloud.Principal{ID: "u1", Name: "user1"}
	p2 := cloud.Principal{ID: "u2", Name: "user2"}
	findings := []cloud.Finding{
		{Type: cloud.FindingWildcardResource, Resource: "*", Principal: &p1},
		{Type: cloud.FindingWildcardResource, Resource: "*", Principal: &p2},
	}
	deduped := dedupFindings(findings)
	if len(deduped) != 2 {
		t.Errorf("expected 2 findings for different principals, got %d", len(deduped))
	}
}
