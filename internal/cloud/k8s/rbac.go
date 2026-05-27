package k8s

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/stxkxs/matlock/internal/cloud"
)

// rbacAPI is the narrow K8s RBAC surface used by this package.
type rbacAPI interface {
	ListClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error)
	ListClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error)
}

type rbacAdapter struct{ clientset *kubernetes.Clientset }

func (a *rbacAdapter) ListClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error) {
	out, err := a.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (a *rbacAdapter) ListClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	out, err := a.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

// dangerousVerbs are verbs that grant write-level power; combined with
// wildcard resources or system groups they constitute admin-level access.
var dangerousVerbs = map[string]bool{
	"*":      true,
	"create": true,
	"update": true,
	"patch":  true,
	"delete": true,
}

// broadSubjectGroups are RBAC groups that include all logged-in users
// (or worse, anonymous). Binding cluster-wide privilege to them is the
// most common Kubernetes misconfiguration.
var broadSubjectGroups = map[string]bool{
	"system:authenticated":   true,
	"system:unauthenticated": true,
	"system:masters":         true, // legitimate use is rare and intentional
	"system:serviceaccounts": true,
	"system:anonymous":       true,
}

// ScanRBAC returns findings for ClusterRoles with overly-broad permissions
// and ClusterRoleBindings that grant privilege to broad subject groups.
//
// Conservative rules — we report what we'd report in a CTF writeup, not
// what a fancy CNAPP would. Specifically:
//
//   - Bindings to cluster-admin always fire (CRITICAL)
//   - Bindings to any role from a broad subject group fire (CRITICAL/HIGH)
//   - ClusterRoles with rules that combine wildcard resources AND any
//     dangerous verb fire (HIGH)
//   - ClusterRoles with wildcard verbs (verbs: ["*"]) fire (HIGH) regardless
//     of resource scope
func (p *Provider) ScanRBAC(ctx context.Context) ([]cloud.K8sFinding, error) {
	roles, err := p.rbac.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cluster roles: %w", err)
	}
	bindings, err := p.rbac.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cluster role bindings: %w", err)
	}

	var findings []cloud.K8sFinding
	findings = append(findings, p.classifyClusterRoles(roles)...)
	findings = append(findings, p.classifyClusterRoleBindings(bindings)...)
	return findings, nil
}

func (p *Provider) classifyClusterRoles(roles []rbacv1.ClusterRole) []cloud.K8sFinding {
	var findings []cloud.K8sFinding
	for _, role := range roles {
		// Skip kubernetes-system default ClusterRoles by name; users
		// can't (and shouldn't) modify these.
		if isSystemReservedRole(role.Name) {
			continue
		}
		for _, rule := range role.Rules {
			wildcardVerb := containsString(rule.Verbs, "*")
			wildcardResource := containsString(rule.Resources, "*")

			if wildcardVerb && wildcardResource {
				findings = append(findings, cloud.K8sFinding{
					Severity:    cloud.SeverityHigh,
					Type:        cloud.K8sClusterAdmin,
					Kind:        "ClusterRole",
					Name:        role.Name,
					ContextName: p.contextName,
					Detail:      "rule grants verbs:[\"*\"] on resources:[\"*\"] — effectively cluster-admin",
					Remediation: fmt.Sprintf("kubectl edit clusterrole %s and replace wildcards with the specific verbs/resources actually needed", role.Name),
				})
				continue
			}
			if wildcardVerb {
				findings = append(findings, cloud.K8sFinding{
					Severity:    cloud.SeverityHigh,
					Type:        cloud.K8sWildcardPermission,
					Kind:        "ClusterRole",
					Name:        role.Name,
					ContextName: p.contextName,
					Detail:      fmt.Sprintf("rule grants verbs:[\"*\"] on resources:%v", rule.Resources),
					Remediation: fmt.Sprintf("kubectl edit clusterrole %s and replace wildcard verb with the actual verbs needed", role.Name),
				})
				continue
			}
			if wildcardResource {
				// Wildcard resource is only worrying when paired with a dangerous verb.
				for _, v := range rule.Verbs {
					if dangerousVerbs[v] {
						findings = append(findings, cloud.K8sFinding{
							Severity:    cloud.SeverityHigh,
							Type:        cloud.K8sWildcardPermission,
							Kind:        "ClusterRole",
							Name:        role.Name,
							ContextName: p.contextName,
							Detail:      fmt.Sprintf("rule grants %q on resources:[\"*\"]", v),
							Remediation: fmt.Sprintf("kubectl edit clusterrole %s and narrow the resource list to what %q actually needs", role.Name, v),
						})
						break
					}
				}
			}
		}
	}
	return findings
}

func (p *Provider) classifyClusterRoleBindings(bindings []rbacv1.ClusterRoleBinding) []cloud.K8sFinding {
	var findings []cloud.K8sFinding
	for _, b := range bindings {
		roleName := b.RoleRef.Name
		toAdmin := roleName == "cluster-admin"

		for _, subject := range b.Subjects {
			subjectName := subject.Name

			// A binding to a broad group is almost always a mistake.
			if subject.Kind == "Group" && broadSubjectGroups[subjectName] {
				sev := cloud.SeverityCritical
				if subjectName == "system:masters" {
					// system:masters is legitimately used by kubeadm/kubectl with the
					// built-in admin certificate; demote to HIGH so it's surfaced but
					// not screaming. system:authenticated/unauthenticated stay CRITICAL.
					sev = cloud.SeverityHigh
				}
				findings = append(findings, cloud.K8sFinding{
					Severity:    sev,
					Type:        cloud.K8sBindingTooBroad,
					Kind:        "ClusterRoleBinding",
					Name:        b.Name,
					ContextName: p.contextName,
					Detail:      fmt.Sprintf("binds ClusterRole %q to group %q — grants cluster-wide privilege to a built-in audience", roleName, subjectName),
					Remediation: fmt.Sprintf("kubectl delete clusterrolebinding %s and replace with a narrower binding (specific users or ServiceAccounts)", b.Name),
				})
				continue
			}

			// Anything bound to cluster-admin is worth reporting even if the
			// subject is specific — cluster-admin is a sledgehammer.
			if toAdmin {
				findings = append(findings, cloud.K8sFinding{
					Severity:    cloud.SeverityHigh,
					Type:        cloud.K8sClusterAdmin,
					Kind:        "ClusterRoleBinding",
					Name:        b.Name,
					ContextName: p.contextName,
					Detail:      fmt.Sprintf("binds cluster-admin to %s %q", subject.Kind, subjectName),
					Remediation: "review whether the subject actually needs cluster-admin; replace with a narrower ClusterRole if not",
				})
			}
		}
	}
	return findings
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// isSystemReservedRole filters out the default ClusterRoles that ship with
// Kubernetes and shouldn't be flagged for user remediation.
func isSystemReservedRole(name string) bool {
	for _, prefix := range []string{
		"system:", "kubeadm:",
	} {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return true
		}
	}
	// Default ClusterRoles by exact name.
	defaults := map[string]bool{
		"cluster-admin": true,
		"admin":         true,
		"edit":          true,
		"view":          true,
	}
	return defaults[name]
}
