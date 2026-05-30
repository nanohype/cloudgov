// Package platform audits live nanohype Platform tenants against the
// eks-agent-platform contract. It is read-only: the operator enforces the
// contract at reconcile time, and this verifies the deployed state still
// matches it (catching drift, manual tampering, and reconcile gaps).
package platform

import (
	"context"
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// GVRs for the eks-agent-platform custom resources the auditor reads. Platform
// and Tenant are in the platform.nanohype.dev group; BudgetPolicy is in
// governance.nanohype.dev. Tenant is cluster-scoped; the others are namespaced.
var (
	platformGVR = schema.GroupVersionResource{Group: "platform.nanohype.dev", Version: "v1alpha1", Resource: "platforms"}
	tenantGVR   = schema.GroupVersionResource{Group: "platform.nanohype.dev", Version: "v1alpha1", Resource: "tenants"}
	budgetGVR   = schema.GroupVersionResource{Group: "governance.nanohype.dev", Version: "v1alpha1", Resource: "budgetpolicies"}
)

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

// RoleReader fetches IAM role detail for IRSA conformance checks. The AWS
// provider implements it; pass nil to skip AWS-side checks (e.g. no credentials).
type RoleReader interface {
	GetRoleInfo(ctx context.Context, roleName string) (*cloud.IAMRoleInfo, error)
}

// Audit lists every Platform CR in the cluster and reports conformance gaps in
// each tenant's namespace and IRSA wiring. Read-only.
func Audit(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface, roles RoleReader) ([]cloud.PlatformFinding, error) {
	list, err := dyn.Resource(platformGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Platform CRs (platform.nanohype.dev/v1alpha1): %w", err)
	}
	var findings []cloud.PlatformFinding
	for i := range list.Items {
		findings = append(findings, auditPlatform(ctx, typed, dyn, roles, &list.Items[i])...)
	}
	return findings, nil
}

func auditPlatform(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface, roles RoleReader, p *unstructured.Unstructured) []cloud.PlatformFinding {
	name := p.GetName()
	tenant, _, _ := unstructured.NestedString(p.Object, "spec", "tenant")
	persona, _, _ := unstructured.NestedString(p.Object, "spec", "persona")
	phase, _, _ := unstructured.NestedString(p.Object, "status", "phase")
	ns, _, _ := unstructured.NestedString(p.Object, "status", "namespace")
	if ns == "" {
		ns = "tenants-" + name
	}
	roleArn, _, _ := unstructured.NestedString(p.Object, "status", "iamRoleArn")
	suspendedAt, _, _ := unstructured.NestedString(p.Object, "status", "suspendedAt")
	suspended := suspendedAt != ""
	extras, _, _ := unstructured.NestedStringSlice(p.Object, "spec", "identity", "extraPolicyArns")

	f := func(sev cloud.Severity, t cloud.PlatformFindingType, resource, detail, remediation string) cloud.PlatformFinding {
		return cloud.PlatformFinding{
			Severity: sev, Type: t, Platform: name, Tenant: tenant,
			Namespace: ns, Resource: resource, Detail: detail, Remediation: remediation,
		}
	}

	var out []cloud.PlatformFinding
	out = append(out, auditIdentity(p, f)...)
	out = append(out, auditBudgetCompliance(ctx, dyn, p, f)...)

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
	if roles != nil && roleArn != "" {
		out = append(out, auditRole(ctx, roles, roleArn, ns, suspended, extras, f)...)
	}
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

// auditRole verifies the tenant IRSA role against the contract: it exists, has
// no inline policies, trusts only the tenant-runtime ServiceAccount, has a
// suspension tag consistent with Platform.status, and carries the declared
// extraPolicyArns (plus a baseline when active).
func auditRole(ctx context.Context, roles RoleReader, roleArn, ns string, suspended bool, extras []string, f findingFunc) []cloud.PlatformFinding {
	name := roleNameFromARN(roleArn)
	if name == "" {
		return nil
	}
	info, err := roles.GetRoleInfo(ctx, name)
	if err != nil {
		return []cloud.PlatformFinding{f(cloud.SeverityInfo, cloud.PlatformNotReady, roleArn, "could not read IAM role: "+err.Error(), "")}
	}
	if info == nil {
		return []cloud.PlatformFinding{f(cloud.SeverityCritical, cloud.PlatformIRSARoleMissing, roleArn,
			"Platform.status.iamRoleArn points to an IAM role that does not exist",
			"The operator provisions the tenant IRSA role; check the reconcile status.")}
	}

	var out []cloud.PlatformFinding

	if len(info.InlinePolicyNames) > 0 {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformIRSAInlinePolicy, roleArn,
			fmt.Sprintf("tenant IRSA role has %d inline policy(ies); the contract uses managed policies only", len(info.InlinePolicyNames)),
			"Remove inline policies and attach managed policies instead."))
	}

	wantSub := "system:serviceaccount:" + ns + ":" + saName
	if !strings.Contains(info.TrustPolicyDocument, wantSub) {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformIRSATrustMismatch, roleArn,
			"trust policy does not constrain AssumeRoleWithWebIdentity to "+wantSub,
			"Reconcile the role's OIDC trust policy to the tenant-runtime ServiceAccount subject."))
	}

	roleSuspended := info.Tags["platform.nanohype.dev/suspended"] == "true"
	if suspended != roleSuspended {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformIRSASuspensionDrift, roleArn,
			fmt.Sprintf("suspension mismatch: Platform.status.suspendedAt set=%t but role suspended tag=%t", suspended, roleSuspended),
			"Reconcile the kill-switch state; the role tag and Platform status must agree."))
	}

	attached := make(map[string]bool, len(info.AttachedPolicyARNs))
	for _, a := range info.AttachedPolicyARNs {
		attached[a] = true
	}
	for _, arn := range extras {
		if arn != "" && !attached[arn] {
			out = append(out, f(cloud.SeverityMedium, cloud.PlatformIRSAExtraPolicyMissing, roleArn,
				"declared spec.identity.extraPolicyArns entry is not attached: "+arn,
				"Attach the declared managed policy, or remove it from the Platform spec."))
		}
	}

	if !suspended && len(info.AttachedPolicyARNs) == 0 {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformIRSANoBaseline, roleArn,
			"role has no managed policies attached; the baseline Bedrock policy is expected on an active tenant",
			"Verify the operator attached the baseline policy (or that the tenant is intentionally suspended)."))
	}
	return out
}

// roleNameFromARN extracts the IAM role name (the final path segment) from a
// role ARN, e.g. arn:aws:iam::123:role/eks-agent-platform/tenants/dev-app1-tenant
// -> dev-app1-tenant.
func roleNameFromARN(arn string) string {
	const sep = ":role/"
	i := strings.Index(arn, sep)
	if i < 0 {
		return ""
	}
	full := arn[i+len(sep):]
	if j := strings.LastIndex(full, "/"); j >= 0 {
		return full[j+1:]
	}
	return full
}

// auditBudgetCompliance checks the Platform's cross-resource invariants: the
// referenced BudgetPolicy exists, SOC2 platforms have the kill-switch enabled,
// and the Platform is at least as strict as its owning Tenant. These are spec
// consistency checks, so they run regardless of phase.
func auditBudgetCompliance(ctx context.Context, dyn dynamic.Interface, p *unstructured.Unstructured, f findingFunc) []cloud.PlatformFinding {
	var out []cloud.PlatformFinding
	ns := p.GetNamespace()
	soc2, _, _ := unstructured.NestedBool(p.Object, "spec", "compliance", "soc2")
	hipaa, _, _ := unstructured.NestedBool(p.Object, "spec", "compliance", "hipaa")

	budgetName, _, _ := unstructured.NestedString(p.Object, "spec", "budget", "name")
	if budgetName == "" {
		out = append(out, f(cloud.SeverityMedium, cloud.PlatformBudgetMissing, "",
			"spec.budget.name is empty; no BudgetPolicy is referenced", "Reference a BudgetPolicy in spec.budget.name."))
	} else {
		bp, err := dyn.Resource(budgetGVR).Namespace(ns).Get(ctx, budgetName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			out = append(out, f(cloud.SeverityHigh, cloud.PlatformBudgetMissing, ns+"/"+budgetName,
				"spec.budget.name references a BudgetPolicy that does not exist", "Create the referenced BudgetPolicy or fix the reference."))
		case err == nil && soc2:
			if killSwitch, _, _ := unstructured.NestedBool(bp.Object, "spec", "killSwitchEnabled"); !killSwitch {
				out = append(out, f(cloud.SeverityHigh, cloud.PlatformKillSwitchDisabled, ns+"/"+budgetName,
					"SOC2 platform's BudgetPolicy has killSwitchEnabled=false", "Enable the budget kill-switch; SOC2 requires it."))
			}
		}
	}

	tenantName, _, _ := unstructured.NestedString(p.Object, "spec", "tenant")
	if tenantName != "" {
		ten, err := dyn.Resource(tenantGVR).Get(ctx, tenantName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			out = append(out, f(cloud.SeverityLow, cloud.PlatformTenantMissing, tenantName,
				"spec.tenant references a Tenant CR that does not exist", "Create the Tenant CR or fix the reference."))
		case err == nil:
			tSOC2, _, _ := unstructured.NestedBool(ten.Object, "spec", "compliance", "soc2")
			tHIPAA, _, _ := unstructured.NestedBool(ten.Object, "spec", "compliance", "hipaa")
			if tSOC2 && !soc2 {
				out = append(out, f(cloud.SeverityHigh, cloud.PlatformComplianceWeaker, tenantName,
					"Tenant requires soc2 but this Platform does not set compliance.soc2", "A Platform must be at least as strict as its Tenant; set compliance.soc2=true."))
			}
			if tHIPAA && !hipaa {
				out = append(out, f(cloud.SeverityHigh, cloud.PlatformComplianceWeaker, tenantName,
					"Tenant requires hipaa but this Platform does not set compliance.hipaa", "Set compliance.hipaa=true to match the Tenant baseline."))
			}
		}
	}
	return out
}
