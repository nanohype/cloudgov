// Package platform audits live nanohype Platform tenants against the
// eks-agent-platform contract. It is read-only: the operator enforces the
// contract at reconcile time, and this verifies the deployed state still
// matches it (catching drift, manual tampering, and reconcile gaps).
package platform

import (
	"context"
	"fmt"
	"sort"
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
	gatewayGVR  = schema.GroupVersionResource{Group: "agents.nanohype.dev", Version: "v1alpha1", Resource: "modelgateways"}
)

const (
	// Canonical ownership labels (resource-tagging standard). The operator
	// stamps these on each tenant namespace.
	platformLabel = "agents.nanohype.dev/platform"
	tenantLabel   = "agents.nanohype.dev/tenant"
	personaLabel  = "agents.nanohype.dev/persona"

	pssEnforce = "pod-security.kubernetes.io/enforce"

	// roleArnAnnotation is the IRSA ServiceAccount annotation. The tenant
	// contract forbids it — the auditor flags its presence, not its absence.
	roleArnAnnotation = "eks.amazonaws.com/role-arn"

	defaultName = "tenant-default" // ResourceQuota + LimitRange
	netpolName  = "tenant-egress"

	// defaultSAName is the ServiceAccount the operator binds under namespace
	// isolation. Under vcluster isolation the bound name is vcluster-translated
	// and unguessable from here, so status.podIdentity is the authority; this is
	// only the fallback when a Platform has not published its binding yet.
	defaultSAName = "tenant-runtime"

	// vclusterIsolation is the spec.isolation value whose bound ServiceAccount
	// is not derivable without the published binding.
	vclusterIsolation = "vcluster"
)

// operatorInlinePolicies is the set of inline policies the eks-agent-platform
// operator reconciles onto a tenant role. Anything else on the role was attached
// by hand: unreviewed privilege on an identity whose whole point is that its
// grants are generated from a declaration.
//
// Kept as an allowlist rather than a ban on inline policies, because inline is
// the contract. The operator generates scoped IAM from spec.datastores,
// spec.identity.capabilities and spec.identity.directSecretReads precisely so
// those grants are not hand-written managed policies.
var operatorInlinePolicies = map[string]bool{
	"bedrock-model-scoping": true,
	"datastore-access":      true,
	"capability-access":     true,
	"tenant-secrets":        true,
	"tenant-key-access":     true,
}

// modelScopingPolicy is written on every non-suspended reconcile regardless of
// spec, so its absence on an active tenant means the tenant's Bedrock access is
// clamped only by the baseline — the per-Platform model scope is not in force.
const modelScopingPolicy = "bedrock-model-scoping"

// podIdentityPrincipal is the service principal in a Pod Identity role's trust
// policy. It is the whole trust document: the (namespace, service-account)
// constraint lives in the association, so every conformant tenant role trusts
// exactly this and nothing narrower.
const podIdentityPrincipal = "pods.eks.amazonaws.com"

// findingFunc builds a PlatformFinding pre-populated with the platform/tenant/
// namespace context for the platform under audit.
type findingFunc func(sev cloud.Severity, t cloud.PlatformFindingType, resource, detail, remediation string) cloud.PlatformFinding

// IdentityReader fetches the AWS-side tenant identity: the IAM role, and the
// Pod Identity association that binds it to a ServiceAccount. The AWS provider
// implements it; pass nil to skip AWS-side checks (e.g. no credentials).
type IdentityReader interface {
	GetRoleInfo(ctx context.Context, roleName string) (*cloud.IAMRoleInfo, error)
	// GetPodIdentityAssociation returns the association binding
	// (namespace, serviceAccount) on a cluster, or (nil, nil) when none exists.
	GetPodIdentityAssociation(ctx context.Context, clusterName, namespace, serviceAccount string) (*cloud.PodIdentityAssociation, error)
}

// Audit lists every Platform CR in the cluster and reports conformance gaps in
// each tenant's namespace and identity wiring. Read-only.
func Audit(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface, roles IdentityReader) ([]cloud.PlatformFinding, error) {
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

func auditPlatform(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface, roles IdentityReader, p *unstructured.Unstructured) []cloud.PlatformFinding {
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
	binding := readBinding(p, ns)

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
	// Ordered (not a map) for deterministic finding output.
	for _, c := range []struct{ key, want string }{
		{platformLabel, name},
		{tenantLabel, tenant},
		{personaLabel, persona},
	} {
		if got := nsObj.Labels[c.key]; got != c.want {
			out = append(out, f(cloud.SeverityLow, cloud.PlatformLabelMissing, ns,
				fmt.Sprintf("namespace label %s is %q, want %q", c.key, orUnset(got), c.want),
				"Restore the agents.nanohype.dev ownership labels (drive cost attribution and network selection)."))
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
	out = append(out, auditServiceAccount(ctx, typed, binding, f)...)
	if roles != nil && roleArn != "" {
		out = append(out, auditRole(ctx, roles, roleArn, suspended, extras, f)...)
		out = append(out, auditPodIdentity(ctx, roles, binding, roleArn, f)...)
	}
	return out
}

// tenantBinding is the Pod Identity binding a Platform reports on
// status.podIdentity, resolved against what this auditor can verify.
type tenantBinding struct {
	clusterName    string
	namespace      string
	serviceAccount string
	roleARN        string

	// published is false when the Platform reports no binding. The auditor
	// still checks the ServiceAccount under namespace isolation, where the
	// bound name is known; under vcluster isolation it can check nothing,
	// because the bound name is vcluster-translated.
	published bool
	// derivable is false when nothing can be checked without the published
	// binding — vcluster isolation with no status.podIdentity.
	derivable bool
}

// readBinding resolves what the auditor knows about a Platform's Pod Identity
// binding. status.podIdentity is authoritative; without it the ServiceAccount is
// tenant-runtime under namespace isolation and unguessable under vcluster
// isolation, where the syncer rewrites it to a translated host name.
func readBinding(p *unstructured.Unstructured, ns string) tenantBinding {
	cluster, _, _ := unstructured.NestedString(p.Object, "status", "podIdentity", "clusterName")
	bns, _, _ := unstructured.NestedString(p.Object, "status", "podIdentity", "namespace")
	sa, _, _ := unstructured.NestedString(p.Object, "status", "podIdentity", "serviceAccount")
	role, _, _ := unstructured.NestedString(p.Object, "status", "podIdentity", "roleArn")
	if sa != "" {
		if bns == "" {
			bns = ns
		}
		return tenantBinding{
			clusterName: cluster, namespace: bns, serviceAccount: sa, roleARN: role,
			published: true, derivable: true,
		}
	}

	isolation, _, _ := unstructured.NestedString(p.Object, "spec", "isolation")
	if isolation == vclusterIsolation {
		return tenantBinding{namespace: ns}
	}
	return tenantBinding{namespace: ns, serviceAccount: defaultSAName, derivable: true}
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

// auditServiceAccount checks the ServiceAccount the Pod Identity association
// actually binds — not a fixed name. Under vcluster isolation the bound
// ServiceAccount is a syncer-translated host name, so a fixed tenant-runtime
// lookup would report every conformant vcluster tenant as missing its SA.
func auditServiceAccount(ctx context.Context, typed kubernetes.Interface, b tenantBinding, f findingFunc) []cloud.PlatformFinding {
	if !b.derivable {
		return []cloud.PlatformFinding{f(cloud.SeverityInfo, cloud.PlatformPodIdentityUnknown, b.namespace,
			"Platform reports no status.podIdentity and uses vcluster isolation; the bound ServiceAccount is syncer-translated and cannot be derived",
			"Re-run once the operator has published status.podIdentity.")}
	}

	ref := b.namespace + "/" + b.serviceAccount
	sa, err := typed.CoreV1().ServiceAccounts(b.namespace).Get(ctx, b.serviceAccount, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return []cloud.PlatformFinding{f(cloud.SeverityHigh, cloud.PlatformServiceAccountMissing, ref,
			fmt.Sprintf("ServiceAccount %s is missing; the Pod Identity association binds it, so tenant pods receive no credentials", b.serviceAccount),
			"Restore the tenant ServiceAccount; the operator reconciles it from the Platform.")}
	}
	if err != nil {
		return nil
	}

	// The contract forbids the role-arn annotation: the association is the
	// binding, and a pasted ARN is an unreconciled second source of truth that
	// drifts silently from the role the operator actually bound.
	if ann := sa.Annotations[roleArnAnnotation]; ann != "" {
		return []cloud.PlatformFinding{f(cloud.SeverityMedium, cloud.PlatformServiceAccountAnnotated, ref,
			fmt.Sprintf("ServiceAccount carries %s=%q; the tenant contract forbids it — the Pod Identity association is the binding",
				roleArnAnnotation, ann),
			"Remove the eks.amazonaws.com/role-arn annotation from the tenant ServiceAccount.")}
	}
	return nil
}

func orUnset(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// auditRole verifies the tenant role against the contract: it exists, trusts the
// EKS Pod Identity service principal, carries the operator's generated inline
// policies and nothing hand-attached, has a suspension tag consistent with
// Platform.status, and carries the declared extraPolicyArns plus a baseline when
// active.
func auditRole(ctx context.Context, roles IdentityReader, roleArn string, suspended bool, extras []string, f findingFunc) []cloud.PlatformFinding {
	name := roleNameFromARN(roleArn)
	if name == "" {
		return nil
	}
	info, err := roles.GetRoleInfo(ctx, name)
	if err != nil {
		return []cloud.PlatformFinding{f(cloud.SeverityInfo, cloud.PlatformNotReady, roleArn, "could not read IAM role: "+err.Error(), "")}
	}
	if info == nil {
		return []cloud.PlatformFinding{f(cloud.SeverityCritical, cloud.PlatformRoleMissing, roleArn,
			"Platform.status.iamRoleArn points to an IAM role that does not exist",
			"The operator provisions the tenant role; check the reconcile status.")}
	}

	var out []cloud.PlatformFinding
	out = append(out, auditTrustPolicy(info.TrustPolicyDocument, roleArn, f)...)
	out = append(out, auditInlinePolicies(info.InlinePolicyNames, roleArn, suspended, f)...)

	roleSuspended := info.Tags["platform.nanohype.dev/suspended"] == "true"
	if suspended != roleSuspended {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformRoleSuspensionDrift, roleArn,
			fmt.Sprintf("suspension mismatch: Platform.status.suspendedAt set=%t but role suspended tag=%t", suspended, roleSuspended),
			"Reconcile the kill-switch state; the role tag and Platform status must agree."))
	}

	attached := make(map[string]bool, len(info.AttachedPolicyARNs))
	for _, a := range info.AttachedPolicyARNs {
		attached[a] = true
	}
	for _, arn := range extras {
		if arn != "" && !attached[arn] {
			out = append(out, f(cloud.SeverityMedium, cloud.PlatformRoleExtraPolicyMissing, roleArn,
				"declared spec.identity.extraPolicyArns entry is not attached: "+arn,
				"Attach the declared managed policy, or remove it from the Platform spec."))
		}
	}

	if !suspended && len(info.AttachedPolicyARNs) == 0 {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformRoleNoBaseline, roleArn,
			"role has no managed policies attached; the baseline Bedrock policy is expected on an active tenant",
			"Verify the operator attached the baseline policy (or that the tenant is intentionally suspended)."))
	}
	return out
}

// auditTrustPolicy asserts the Pod Identity trust shape. It deliberately does
// not look for a ServiceAccount subject: under Pod Identity there is none, and
// the presence of a web-identity trust means the role is still wired for the
// retired IRSA path.
func auditTrustPolicy(doc, roleArn string, f findingFunc) []cloud.PlatformFinding {
	if strings.Contains(doc, "AssumeRoleWithWebIdentity") {
		return []cloud.PlatformFinding{f(cloud.SeverityHigh, cloud.PlatformRoleTrustMismatch, roleArn,
			"trust policy grants sts:AssumeRoleWithWebIdentity; the tenant role is assumed through EKS Pod Identity, not an OIDC provider",
			"Reconcile the role's trust policy to the "+podIdentityPrincipal+" service principal.")}
	}
	if !strings.Contains(doc, podIdentityPrincipal) {
		return []cloud.PlatformFinding{f(cloud.SeverityHigh, cloud.PlatformRoleTrustMismatch, roleArn,
			"trust policy does not allow the "+podIdentityPrincipal+" service principal; no Pod Identity association can vend this role",
			"Reconcile the role's trust policy to the "+podIdentityPrincipal+" service principal.")}
	}
	return nil
}

// auditInlinePolicies checks inline policies against the operator's allowlist in
// both directions: nothing unexpected, and the always-written model scope
// present. Inline policies are the contract, not a violation of it — the
// operator generates scoped IAM from the Platform spec.
//
// Both checks are skipped on a suspended tenant: the operator is observe-only
// under the kill-switch and writes no policy, so a suspended role's inline set
// is whatever the kill-switch left behind.
func auditInlinePolicies(names []string, roleArn string, suspended bool, f findingFunc) []cloud.PlatformFinding {
	if suspended {
		return nil
	}

	var out []cloud.PlatformFinding
	var unexpected []string
	var hasModelScope bool
	for _, n := range names {
		if n == modelScopingPolicy {
			hasModelScope = true
		}
		if !operatorInlinePolicies[n] {
			unexpected = append(unexpected, n)
		}
	}

	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformRoleInlineUnexpected, roleArn,
			"tenant role carries inline policies the operator does not generate: "+strings.Join(unexpected, ", "),
			"Remove hand-attached inline policies; express the grant as spec.datastores, spec.identity.capabilities, or spec.identity.directSecretReads so the operator generates and reconciles it."))
	}
	if !hasModelScope {
		out = append(out, f(cloud.SeverityHigh, cloud.PlatformRoleModelScopeMissing, roleArn,
			"tenant role has no "+modelScopingPolicy+" inline policy; the operator writes it on every reconcile, so the per-Platform model scope is not in force",
			"Check the Platform reconcile status; the model-scoping policy is generated from spec.identity."))
	}
	return out
}

// auditPodIdentity verifies the binding itself — the association that vends the
// tenant role to tenant pods. This is the only place tenancy is observable: the
// role's trust policy carries no subject, so a conformant trust document is
// identical for every tenant in the account.
func auditPodIdentity(ctx context.Context, roles IdentityReader, b tenantBinding, roleArn string, f findingFunc) []cloud.PlatformFinding {
	if !b.published || b.clusterName == "" {
		return []cloud.PlatformFinding{f(cloud.SeverityInfo, cloud.PlatformPodIdentityUnknown, b.namespace,
			"Platform reports no status.podIdentity binding; the Pod Identity association was not verified",
			"Re-run once the operator has published status.podIdentity.")}
	}

	ref := b.namespace + "/" + b.serviceAccount
	assoc, err := roles.GetPodIdentityAssociation(ctx, b.clusterName, b.namespace, b.serviceAccount)
	if err != nil {
		return []cloud.PlatformFinding{f(cloud.SeverityInfo, cloud.PlatformNotReady, ref,
			"could not read the Pod Identity association: "+err.Error(), "")}
	}
	if assoc == nil {
		return []cloud.PlatformFinding{f(cloud.SeverityHigh, cloud.PlatformPodIdentityMissing, ref,
			fmt.Sprintf("no Pod Identity association binds %s on cluster %s; tenant pods receive no AWS credentials", ref, b.clusterName),
			"Check the Platform reconcile status; the operator creates the association alongside the tenant role.")}
	}
	if assoc.RoleARN != roleArn {
		return []cloud.PlatformFinding{f(cloud.SeverityCritical, cloud.PlatformPodIdentityMismatch, ref,
			fmt.Sprintf("Pod Identity association binds %s to %q, not the Platform's own role %q; tenant pods run with a foreign identity",
				ref, assoc.RoleARN, roleArn),
			"Delete the association and let the operator recreate it against the Platform's tenant role.")}
	}
	return nil
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

	if hipaa {
		out = append(out, auditHipaaGuardrails(ctx, dyn, p, f)...)
	}
	return out
}

// auditHipaaGuardrails requires a hipaa Platform's model routes to name a
// guardrail rather than fall back to the cluster baseline.
//
// Every route resolves to a guardrail: the route's own guardrailRef, else the
// gateway's defaultGuardrailRef, else the baseline the operator reads from SSM.
// That fallback is the point of the baseline and the right default for a general
// workload — but it is a general-purpose guardrail, and a route reaching it does
// so by omission rather than by anyone choosing it.
//
// The check is that a decision was made, not what the decision was. Whether a
// named guardrail carries the right PII entities and blocks rather than
// anonymizes is a question about Bedrock state, which this audit does not read;
// declaring HIPAA and silently inheriting a default is answerable from the CRs
// alone.
func auditHipaaGuardrails(ctx context.Context, dyn dynamic.Interface, p *unstructured.Unstructured, f findingFunc) []cloud.PlatformFinding {
	ns := p.GetNamespace()
	gws, err := dyn.Resource(gatewayGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		// A gateway the audit cannot read is not a gateway the audit can clear.
		// Reporting nothing here would read as "no finding" on a Platform whose
		// routes were never examined.
		return []cloud.PlatformFinding{f(cloud.SeverityLow, cloud.PlatformHipaaGuardrailInherited, "",
			"hipaa platform's ModelGateways could not be listed, so their guardrails were not checked",
			"Re-run with permission to list modelgateways in this namespace.")}
	}

	var out []cloud.PlatformFinding
	for _, gw := range gws.Items {
		if owner, _, _ := unstructured.NestedString(gw.Object, "spec", "platformRef", "name"); owner != p.GetName() {
			continue
		}
		gwDefault, _, _ := unstructured.NestedString(gw.Object, "spec", "defaultGuardrailRef", "name")
		if gwDefault != "" {
			continue // covers every route on this gateway
		}
		routes, _, _ := unstructured.NestedSlice(gw.Object, "spec", "routes")
		for _, r := range routes {
			route, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if ref, _, _ := unstructured.NestedString(route, "guardrailRef", "name"); ref != "" {
				continue
			}
			name, _, _ := unstructured.NestedString(route, "name")
			out = append(out, f(cloud.SeverityHigh, cloud.PlatformHipaaGuardrailInherited, ns+"/"+gw.GetName()+"/"+name,
				"hipaa platform's route "+name+" names no guardrail, so it falls back to the cluster baseline",
				"Set spec.routes[].guardrailRef, or the gateway's spec.defaultGuardrailRef, to a guardrail chosen for this workload."))
		}
	}
	return out
}
