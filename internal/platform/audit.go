// Package platform audits live nanohype Platform tenants against the
// eks-agent-platform contract. It is read-only: the operator enforces the
// contract at reconcile time, and this verifies the deployed state still
// matches it (catching drift, manual tampering, and reconcile gaps).
package platform

import (
	"context"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// platformGVR is the Platform custom resource (eks-agent-platform operator).
var platformGVR = schema.GroupVersionResource{
	Group:    "agents.stxkxs.io",
	Version:  "v1alpha1",
	Resource: "platforms",
}

const (
	platformLabel  = "eks-agent-platform/platform"
	tenantLabel    = "eks-agent-platform/tenant"
	personaLabel   = "eks-agent-platform/persona"
	pssEnforce     = "pod-security.kubernetes.io/enforce"
	irsaAnnotation = "eks.amazonaws.com/role-arn"

	defaultName = "tenant-default" // ResourceQuota + LimitRange
	netpolName  = "tenant-egress"
	saName      = "tenant-runtime"
)

// findingFunc builds a PlatformFinding pre-populated with the platform/tenant/
// namespace context for the platform under audit.
type findingFunc func(sev cloud.Severity, t cloud.PlatformFindingType, resource, detail, remediation string) cloud.PlatformFinding

// Audit lists every Platform CR in the cluster and reports conformance gaps in
// each tenant's namespace and IRSA wiring. Read-only.
func Audit(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface) ([]cloud.PlatformFinding, error) {
	list, err := dyn.Resource(platformGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Platform CRs (agents.stxkxs.io/v1alpha1): %w", err)
	}
	var findings []cloud.PlatformFinding
	for i := range list.Items {
		findings = append(findings, auditPlatform(ctx, typed, &list.Items[i])...)
	}
	return findings, nil
}

func auditPlatform(ctx context.Context, typed kubernetes.Interface, p *unstructured.Unstructured) []cloud.PlatformFinding {
	name := p.GetName()
	tenant, _, _ := unstructured.NestedString(p.Object, "spec", "tenant")
	persona, _, _ := unstructured.NestedString(p.Object, "spec", "persona")
	phase, _, _ := unstructured.NestedString(p.Object, "status", "phase")
	ns, _, _ := unstructured.NestedString(p.Object, "status", "namespace")
	if ns == "" {
		ns = "tenants-" + name
	}
	roleArn, _, _ := unstructured.NestedString(p.Object, "status", "iamRoleArn")

	f := func(sev cloud.Severity, t cloud.PlatformFindingType, resource, detail, remediation string) cloud.PlatformFinding {
		return cloud.PlatformFinding{
			Severity: sev, Type: t, Platform: name, Tenant: tenant,
			Namespace: ns, Resource: resource, Detail: detail, Remediation: remediation,
		}
	}

	var out []cloud.PlatformFinding
	out = append(out, auditIdentity(p, f)...)

	// Only Ready/Suspended platforms are expected to be fully provisioned. For
	// the rest, namespace conformance gaps are expected (still provisioning).
	if phase != "Ready" && phase != "Suspended" {
		return append(out, f(cloud.SeverityInfo, cloud.PlatformNotReady, "",
			fmt.Sprintf("phase is %q; skipping namespace conformance checks", orUnset(phase)),
			"Re-run once the Platform reaches Ready."))
	}

	nsObj, err := typed.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return append(out, f(cloud.SeverityCritical, cloud.PlatformNamespaceMissing, ns,
				"tenant namespace does not exist", "Check the Platform reconcile status; the operator provisions the namespace."))
		}
		return append(out, f(cloud.SeverityInfo, cloud.PlatformNotReady, ns, "could not read tenant namespace: "+err.Error(), ""))
	}

	if nsObj.Labels[pssEnforce] != "restricted" {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformPSSNotRestricted, ns,
			fmt.Sprintf("namespace %s is %q, want restricted", pssEnforce, orUnset(nsObj.Labels[pssEnforce])),
			"Restore the restricted Pod Security Standards label on the tenant namespace."))
	}
	for key, want := range map[string]string{platformLabel: name, tenantLabel: tenant, personaLabel: persona} {
		if nsObj.Labels[key] != want {
			out = append(out, f(cloud.SeverityLow, cloud.PlatformLabelMissing, ns,
				fmt.Sprintf("namespace label %s is %q, want %q", key, orUnset(nsObj.Labels[key]), want),
				"Restore the eks-agent-platform ownership labels (drive cost attribution and network selection)."))
		}
	}

	if _, err := typed.CoreV1().ResourceQuotas(ns).Get(ctx, defaultName, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformQuotaMissing, ns+"/"+defaultName,
			"tenant ResourceQuota is missing; the namespace can consume unbounded cluster resources",
			"Restore the tenant-default ResourceQuota."))
	}
	if _, err := typed.CoreV1().LimitRanges(ns).Get(ctx, defaultName, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		out = append(out, f(cloud.SeverityMedium, cloud.PlatformLimitRangeMissing, ns+"/"+defaultName,
			"tenant LimitRange is missing; pods without explicit resources may breach the quota",
			"Restore the tenant-default LimitRange."))
	}

	out = append(out, auditNetworkPolicy(ctx, typed, ns, f)...)
	out = append(out, auditServiceAccount(ctx, typed, ns, roleArn, f)...)
	return out
}

func auditIdentity(p *unstructured.Unstructured, f findingFunc) []cloud.PlatformFinding {
	models, _, _ := unstructured.NestedStringSlice(p.Object, "spec", "identity", "allowedModels")
	families, _, _ := unstructured.NestedStringSlice(p.Object, "spec", "identity", "allowedModelFamilies")
	switch {
	case len(models) > 0 && len(families) > 0:
		return []cloud.PlatformFinding{f(cloud.SeverityMedium, cloud.PlatformIdentityInvalid, "",
			"spec.identity sets both allowedModels and allowedModelFamilies (mutually exclusive)",
			"Set only one of allowedModels or allowedModelFamilies.")}
	case len(models) == 0 && len(families) == 0:
		return []cloud.PlatformFinding{f(cloud.SeverityMedium, cloud.PlatformIdentityInvalid, "",
			"spec.identity sets neither allowedModels nor allowedModelFamilies; the tenant role can invoke no Bedrock models",
			"Set allowedModels or allowedModelFamilies.")}
	}
	return nil
}

func auditNetworkPolicy(ctx context.Context, typed kubernetes.Interface, ns string, f findingFunc) []cloud.PlatformFinding {
	np, err := typed.NetworkingV1().NetworkPolicies(ns).Get(ctx, netpolName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return []cloud.PlatformFinding{f(cloud.SeverityCritical, cloud.PlatformNetworkPolicyMissing, ns+"/"+netpolName,
			"tenant-egress NetworkPolicy is missing; the tenant has no egress containment",
			"Restore the tenant-egress default-deny + allow-list NetworkPolicy.")}
	}
	if err != nil {
		return nil
	}

	var out []cloud.PlatformFinding
	var hasEgress, hasIngress bool
	for _, t := range np.Spec.PolicyTypes {
		switch t {
		case networkingv1.PolicyTypeEgress:
			hasEgress = true
		case networkingv1.PolicyTypeIngress:
			hasIngress = true
		}
	}
	if !hasEgress {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformNetworkPolicyWeak, ns+"/"+netpolName,
			"tenant-egress NetworkPolicy does not restrict egress (no Egress policy type)",
			"Ensure PolicyTypes includes Egress so tenant egress is default-deny + allow-list."))
	}
	if hasIngress {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformNetworkPolicyWeak, ns+"/"+netpolName,
			"tenant-egress NetworkPolicy declares Ingress rules; the contract is egress-only with ingress default-deny",
			"Remove Ingress policy types/rules from the tenant NetworkPolicy."))
	}
	if len(np.Spec.PodSelector.MatchLabels) > 0 || len(np.Spec.PodSelector.MatchExpressions) > 0 {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformNetworkPolicyWeak, ns+"/"+netpolName,
			"tenant-egress NetworkPolicy is scoped to a subset of pods; it must apply to the whole namespace",
			"Set an empty podSelector so the policy covers all tenant pods."))
	}
	return out
}

func auditServiceAccount(ctx context.Context, typed kubernetes.Interface, ns, roleArn string, f findingFunc) []cloud.PlatformFinding {
	sa, err := typed.CoreV1().ServiceAccounts(ns).Get(ctx, saName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return []cloud.PlatformFinding{f(cloud.SeverityHigh, cloud.PlatformServiceAccountMissing, ns+"/"+saName,
			"tenant-runtime ServiceAccount is missing; tenant workloads cannot assume the IRSA role",
			"Restore the tenant-runtime ServiceAccount.")}
	}
	if err != nil {
		return nil
	}
	ann := sa.Annotations[irsaAnnotation]
	if ann == "" {
		return []cloud.PlatformFinding{f(cloud.SeverityHigh, cloud.PlatformIRSAAnnotationMissing, ns+"/"+saName,
			"tenant-runtime ServiceAccount lacks the eks.amazonaws.com/role-arn annotation",
			"Annotate the ServiceAccount with the tenant IRSA role ARN.")}
	}
	if roleArn != "" && ann != roleArn {
		return []cloud.PlatformFinding{f(cloud.SeverityHigh, cloud.PlatformIRSARoleMismatch, ns+"/"+saName,
			fmt.Sprintf("ServiceAccount role-arn %q does not match Platform.status.iamRoleArn %q", ann, roleArn),
			"Reconcile the ServiceAccount IRSA annotation to the operator-provisioned role.")}
	}
	return nil
}

func orUnset(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}
