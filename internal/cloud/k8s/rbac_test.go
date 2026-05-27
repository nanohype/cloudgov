package k8s

import (
	"context"
	"errors"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockRBAC struct {
	roles       []rbacv1.ClusterRole
	bindings    []rbacv1.ClusterRoleBinding
	rolesErr    error
	bindingsErr error
}

func (m *mockRBAC) ListClusterRoles(_ context.Context) ([]rbacv1.ClusterRole, error) {
	return m.roles, m.rolesErr
}
func (m *mockRBAC) ListClusterRoleBindings(_ context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	return m.bindings, m.bindingsErr
}

func role(name string, rules ...rbacv1.PolicyRule) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules:      rules,
	}
}

func binding(name, roleName string, subjects ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Name: roleName, Kind: "ClusterRole"},
		Subjects:   subjects,
	}
}

func TestScanRBAC_WildcardEverythingIsHigh(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{roles: []rbacv1.ClusterRole{
		role("super-power", rbacv1.PolicyRule{
			Verbs:     []string{"*"},
			Resources: []string{"*"},
			APIGroups: []string{"*"},
		}),
	}}}
	got, err := p.ScanRBAC(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != cloud.SeverityHigh || got[0].Type != cloud.K8sClusterAdmin {
		t.Errorf("expected HIGH cluster-admin, got %+v", got[0])
	}
	if got[0].Name != "super-power" {
		t.Errorf("name: got %q", got[0].Name)
	}
}

func TestScanRBAC_WildcardVerbAlone(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{roles: []rbacv1.ClusterRole{
		role("all-secrets", rbacv1.PolicyRule{
			Verbs:     []string{"*"},
			Resources: []string{"secrets"},
		}),
	}}}
	got, _ := p.ScanRBAC(context.Background())
	if len(got) != 1 || got[0].Type != cloud.K8sWildcardPermission {
		t.Errorf("expected WILDCARD_PERMISSION, got %v", got)
	}
}

func TestScanRBAC_WildcardResourceWithDangerousVerb(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{roles: []rbacv1.ClusterRole{
		role("delete-anything", rbacv1.PolicyRule{
			Verbs:     []string{"delete"},
			Resources: []string{"*"},
		}),
	}}}
	got, _ := p.ScanRBAC(context.Background())
	if len(got) != 1 || got[0].Severity != cloud.SeverityHigh {
		t.Errorf("expected HIGH for delete-on-wildcard, got %v", got)
	}
}

func TestScanRBAC_WildcardResourceWithReadOnlyVerbIsOK(t *testing.T) {
	// "list" and "get" don't trigger — only dangerous verbs do
	p := &Provider{rbac: &mockRBAC{roles: []rbacv1.ClusterRole{
		role("monitor", rbacv1.PolicyRule{
			Verbs:     []string{"get", "list", "watch"},
			Resources: []string{"*"},
		}),
	}}}
	got, _ := p.ScanRBAC(context.Background())
	if len(got) != 0 {
		t.Errorf("read-only on wildcard should be safe, got %v", got)
	}
}

func TestScanRBAC_SystemRolesSkipped(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{roles: []rbacv1.ClusterRole{
		role("system:masters-helper", rbacv1.PolicyRule{
			Verbs:     []string{"*"},
			Resources: []string{"*"},
		}),
		role("cluster-admin", rbacv1.PolicyRule{ // also a default
			Verbs:     []string{"*"},
			Resources: []string{"*"},
		}),
	}}}
	got, _ := p.ScanRBAC(context.Background())
	if len(got) != 0 {
		t.Errorf("system/default roles should be skipped, got %v", got)
	}
}

func TestScanRBAC_BindingToAuthenticatedGroup(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{bindings: []rbacv1.ClusterRoleBinding{
		binding("oops", "edit", rbacv1.Subject{
			Kind: "Group", Name: "system:authenticated",
		}),
	}}}
	got, _ := p.ScanRBAC(context.Background())
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(got), got)
	}
	if got[0].Severity != cloud.SeverityCritical || got[0].Type != cloud.K8sBindingTooBroad {
		t.Errorf("expected CRITICAL BINDING_TOO_BROAD, got %+v", got[0])
	}
}

func TestScanRBAC_BindingToMastersIsHigh(t *testing.T) {
	// system:masters is technically broad but legitimately used by kubeadm
	p := &Provider{rbac: &mockRBAC{bindings: []rbacv1.ClusterRoleBinding{
		binding("kubeadm-binding", "cluster-admin", rbacv1.Subject{
			Kind: "Group", Name: "system:masters",
		}),
	}}}
	got, _ := p.ScanRBAC(context.Background())
	// Two findings: broad-group + cluster-admin (specific subject)
	// Actually subject is a Group, so cluster-admin block fires too — let's just check the broad-group one exists at HIGH
	foundBroad := false
	for _, f := range got {
		if f.Type == cloud.K8sBindingTooBroad && f.Severity == cloud.SeverityHigh {
			foundBroad = true
		}
	}
	if !foundBroad {
		t.Errorf("expected HIGH BINDING_TOO_BROAD for system:masters, got %v", got)
	}
}

func TestScanRBAC_BindingToClusterAdminWithUser(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{bindings: []rbacv1.ClusterRoleBinding{
		binding("alice-admin", "cluster-admin", rbacv1.Subject{
			Kind: "User", Name: "alice@example.com",
		}),
	}}}
	got, _ := p.ScanRBAC(context.Background())
	if len(got) != 1 || got[0].Type != cloud.K8sClusterAdmin || got[0].Severity != cloud.SeverityHigh {
		t.Errorf("expected HIGH CLUSTER_ADMIN for user binding, got %v", got)
	}
}

func TestScanRBAC_NormalBindingIsSilent(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{bindings: []rbacv1.ClusterRoleBinding{
		binding("dev-team", "view", rbacv1.Subject{
			Kind: "Group", Name: "dev-team@example.com",
		}),
	}}}
	got, _ := p.ScanRBAC(context.Background())
	if len(got) != 0 {
		t.Errorf("specific group binding to view should be silent, got %v", got)
	}
}

func TestScanRBAC_ListClusterRolesError(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{rolesErr: errors.New("forbidden")}}
	_, err := p.ScanRBAC(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestScanRBAC_ListBindingsError(t *testing.T) {
	p := &Provider{rbac: &mockRBAC{bindingsErr: errors.New("forbidden")}}
	_, err := p.ScanRBAC(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestContainsString(t *testing.T) {
	if !containsString([]string{"a", "b", "*"}, "*") {
		t.Error("should match wildcard")
	}
	if containsString([]string{"a", "b"}, "*") {
		t.Error("should not match missing element")
	}
	if containsString(nil, "*") {
		t.Error("nil slice should not match")
	}
}

func TestIsSystemReservedRole(t *testing.T) {
	tests := map[string]bool{
		"system:basic-user":  true,
		"system:masters":     true,
		"kubeadm:nodes":      true,
		"cluster-admin":      true,
		"admin":              true,
		"edit":               true,
		"view":               true,
		"my-custom-role":     false,
		"super-admin-helper": false,
	}
	for name, want := range tests {
		got := isSystemReservedRole(name)
		if got != want {
			t.Errorf("isSystemReservedRole(%q): got %v, want %v", name, got, want)
		}
	}
}
