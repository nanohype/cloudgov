package platform

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/nanohype/cloudgov/internal/cloud"
)

const (
	tName    = "app1"
	tNS      = "tenants-app1"
	tMgmtNS  = "eks-agent-platform"
	tTen     = "acme"
	tPers    = "eng"
	tBudget  = "tenant-budget"
	tRole    = "arn:aws:iam::123456789012:role/dev-app1-tenant"
	tCluster = "development-cluster"

	// podIdentityTrust is what the operator writes on every tenant role: the EKS
	// service principal and nothing else. There is no ServiceAccount subject —
	// the binding lives in the association — so this document is byte-identical
	// for every tenant in the account.
	podIdentityTrust = `{"Statement":[{"Action":["sts:AssumeRole","sts:TagSession"],"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"}}],"Version":"2012-10-17"}`
)

func platformCR(phase string, families []string) *unstructured.Unstructured {
	fam := make([]interface{}, len(families))
	for i, s := range families {
		fam[i] = s
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "platform.nanohype.dev/v1alpha1",
		"kind":       "Platform",
		"metadata":   map[string]interface{}{"name": tName, "namespace": tMgmtNS},
		"spec": map[string]interface{}{
			"tenant":   tTen,
			"persona":  tPers,
			"budget":   map[string]interface{}{"name": tBudget},
			"identity": map[string]interface{}{"allowedModelFamilies": fam},
		},
		"status": map[string]interface{}{
			"phase": phase, "namespace": tNS, "iamRoleArn": tRole,
			"podIdentity": map[string]interface{}{
				"clusterName": tCluster, "namespace": tNS, "serviceAccount": defaultSAName, "roleArn": tRole,
			},
		},
	}}
}

// vclusterPlatformCR is a vcluster-isolated Platform whose binding the operator
// has not published yet. The bound ServiceAccount is syncer-translated, so
// nothing about it is derivable from here.
func vclusterPlatformCR() *unstructured.Unstructured {
	cr := platformCR("Ready", []string{"anthropic"})
	_ = unstructured.SetNestedField(cr.Object, vclusterIsolation, "spec", "isolation")
	unstructured.RemoveNestedField(cr.Object, "status", "podIdentity")
	return cr
}

func platformCRCompliance(soc2, hipaa bool) *unstructured.Unstructured {
	cr := platformCR("Ready", []string{"anthropic"})
	_ = unstructured.SetNestedField(cr.Object, soc2, "spec", "compliance", "soc2")
	_ = unstructured.SetNestedField(cr.Object, hipaa, "spec", "compliance", "hipaa")
	return cr
}

func budgetCR(killSwitch bool) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "governance.nanohype.dev/v1alpha1",
		"kind":       "BudgetPolicy",
		"metadata":   map[string]interface{}{"name": tBudget, "namespace": tMgmtNS},
		"spec":       map[string]interface{}{"killSwitchEnabled": killSwitch},
	}}
}

func tenantCR(soc2, hipaa bool) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "platform.nanohype.dev/v1alpha1",
		"kind":       "Tenant",
		"metadata":   map[string]interface{}{"name": tTen}, // cluster-scoped
		"spec":       map[string]interface{}{"compliance": map[string]interface{}{"soc2": soc2, "hipaa": hipaa}},
	}}
}

// gatewayCR is a ModelGateway owned by ownerPlatform. defaultRef is the
// gateway-wide guardrail ("" for none); routes maps a route name to its own
// guardrailRef ("" for none, i.e. the route falls back).
func gatewayCR(name, ownerPlatform, defaultRef string, routes map[string]string) *unstructured.Unstructured {
	rs := make([]interface{}, 0, len(routes))
	for _, rn := range sortedKeys(routes) {
		route := map[string]interface{}{"name": rn}
		if routes[rn] != "" {
			route["guardrailRef"] = map[string]interface{}{"name": routes[rn]}
		}
		rs = append(rs, route)
	}
	spec := map[string]interface{}{
		"platformRef": map[string]interface{}{"name": ownerPlatform},
		"routes":      rs,
	}
	if defaultRef != "" {
		spec["defaultGuardrailRef"] = map[string]interface{}{"name": defaultRef}
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "agents.nanohype.dev/v1alpha1",
		"kind":       "ModelGateway",
		"metadata":   map[string]interface{}{"name": name, "namespace": tMgmtNS},
		"spec":       spec,
	}}
}

// sortedKeys keeps the rendered route order deterministic so a finding's
// resource string is stable across runs.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// addGateways seeds ModelGateways under the resource the audit actually queries.
//
// They cannot be passed to dynClient as constructor objects: the fake files an
// object under meta.UnsafeGuessKindToResource(kind), which lowercases the kind
// and turns a trailing "y" into "ies" — so "ModelGateway" lands under
// "modelgatewaies" while the CRD's real plural, and gatewayGVR, is
// "modelgateways". Nothing errors; List simply returns an empty set, and a test
// asserting a finding fails while a test asserting its absence passes for the
// wrong reason. Tracker().Create takes the GVR explicitly and sidesteps the guess.
func addGateways(t *testing.T, dyn *dynamicfake.FakeDynamicClient, gws ...*unstructured.Unstructured) {
	t.Helper()
	for _, gw := range gws {
		if err := dyn.Tracker().Create(gatewayGVR, gw, gw.GetNamespace()); err != nil {
			t.Fatalf("seed ModelGateway %s: %v", gw.GetName(), err)
		}
	}
}

func dynClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			platformGVR: "PlatformList",
			budgetGVR:   "BudgetPolicyList",
			tenantGVR:   "TenantList",
			gatewayGVR:  "ModelGatewayList",

			ciliumNetworkPolicyGVR: "CiliumNetworkPolicyList",
		},
		objs...,
	)
}

// conformantDyn returns a dynamic client where the Platform, its BudgetPolicy,
// and its Tenant all satisfy the cross-resource invariants.
func conformantDyn() *dynamicfake.FakeDynamicClient {
	return dynClient(platformCR("Ready", []string{"anthropic"}), budgetCR(true), tenantCR(false, false))
}

func types(findings []cloud.PlatformFinding) map[cloud.PlatformFindingType]bool {
	m := make(map[cloud.PlatformFindingType]bool, len(findings))
	for _, f := range findings {
		m[f.Type] = true
	}
	return m
}

func conformantObjects() []runtime.Object {
	return []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tNS, Labels: map[string]string{
			pssEnforce: "restricted", platformLabel: tName, tenantLabel: tTen, personaLabel: tPers,
		}}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: defaultName, Namespace: tNS}},
		&corev1.LimitRange{ObjectMeta: metav1.ObjectMeta{Name: defaultName, Namespace: tNS}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: netpolName, Namespace: tNS},
			Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}},
		},
		// No role-arn annotation: the contract forbids it, so its absence is
		// what conformance looks like.
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: defaultSAName, Namespace: tNS}},
	}
}

type fakeRoles struct {
	info *cloud.IAMRoleInfo
	err  error

	// assoc is the Pod Identity association keyed "<namespace>/<serviceAccount>";
	// a miss means no association binds that pair.
	assoc    map[string]*cloud.PodIdentityAssociation
	assocErr error
}

func (f fakeRoles) GetRoleInfo(context.Context, string) (*cloud.IAMRoleInfo, error) {
	return f.info, f.err
}

func (f fakeRoles) GetPodIdentityAssociation(_ context.Context, _, ns, sa string) (*cloud.PodIdentityAssociation, error) {
	if f.assocErr != nil {
		return nil, f.assocErr
	}
	return f.assoc[ns+"/"+sa], nil
}

// conformantRole is a tenant role as the operator actually reconciles it: Pod
// Identity trust, the always-written model-scoping policy plus generated scoped
// policies inline, the baseline attached, and an association binding it to the
// tenant ServiceAccount.
func conformantRole() fakeRoles {
	return fakeRoles{
		info: &cloud.IAMRoleInfo{
			ARN:                 tRole,
			TrustPolicyDocument: podIdentityTrust,
			Tags:                map[string]string{},
			AttachedPolicyARNs:  []string{"arn:aws:iam::123456789012:policy/tenant-baseline"},
			InlinePolicyNames:   []string{"bedrock-model-scoping", "datastore-access", "tenant-key-access"},
		},
		assoc: map[string]*cloud.PodIdentityAssociation{
			tNS + "/" + defaultSAName: {RoleARN: tRole, Namespace: tNS, ServiceAccount: defaultSAName},
		},
	}
}

func TestAudit_Conformant(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	findings, err := Audit(context.Background(), typed, conformantDyn(), conformantRole())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("conformant platform should have 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestAudit_DriftDetected(t *testing.T) {
	// Namespace exists but PSS is wrong; NetworkPolicy and ServiceAccount absent.
	typed := kubefake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tNS, Labels: map[string]string{
			platformLabel: tName, tenantLabel: tTen, personaLabel: tPers,
		}}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: defaultName, Namespace: tNS}},
		&corev1.LimitRange{ObjectMeta: metav1.ObjectMeta{Name: defaultName, Namespace: tNS}},
	)
	findings, err := Audit(context.Background(), typed, conformantDyn(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := types(findings)
	for _, want := range []cloud.PlatformFindingType{
		cloud.PlatformPSSNotRestricted,
		cloud.PlatformNetworkPolicyMissing,
		cloud.PlatformServiceAccountMissing,
	} {
		if !got[want] {
			t.Errorf("expected finding %s, not present in %+v", want, got)
		}
	}
}

func TestAudit_NamespaceMissing(t *testing.T) {
	typed := kubefake.NewSimpleClientset()
	findings, err := Audit(context.Background(), typed, conformantDyn(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformNamespaceMissing] {
		t.Fatalf("expected NAMESPACE_MISSING, got %+v", findings)
	}
}

func TestAudit_NotReadySkipsResourceChecks(t *testing.T) {
	typed := kubefake.NewSimpleClientset()
	findings, err := Audit(context.Background(), typed, dynClient(platformCR("Pending", []string{"anthropic"}), budgetCR(true), tenantCR(false, false)), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := types(findings)
	if !got[cloud.PlatformNotReady] {
		t.Errorf("expected NOT_READY note, got %+v", findings)
	}
	if got[cloud.PlatformNamespaceMissing] {
		t.Error("must not flag missing resources for a not-yet-Ready platform")
	}
}

func TestAudit_IdentityInvalid(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	findings, err := Audit(context.Background(), typed, dynClient(platformCR("Ready", nil), budgetCR(true), tenantCR(false, false)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformIdentityInvalid] {
		t.Fatalf("expected IDENTITY_INVALID when no models declared, got %+v", findings)
	}
}

func TestAudit_TenantRoleMissing(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	findings, err := Audit(context.Background(), typed, conformantDyn(), fakeRoles{info: nil})
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformRoleMissing] {
		t.Fatalf("expected TENANT_ROLE_MISSING when the role is absent, got %+v", findings)
	}
}

// TestAudit_RetiredIRSAWiringIsTheDrift is the regression pin. Every element of
// this fixture is what the auditor used to call conformant: a role-arn
// annotation on the ServiceAccount, an OIDC web-identity trust policy, and no
// inline policies. Under the Pod Identity contract each one is drift, so the
// auditor's verdict on this shape has to be the exact inverse of what it was.
func TestAudit_RetiredIRSAWiringIsTheDrift(t *testing.T) {
	objs := conformantObjects()
	objs[len(objs)-1] = &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: defaultSAName, Namespace: tNS,
		Annotations: map[string]string{roleArnAnnotation: tRole},
	}}
	typed := kubefake.NewSimpleClientset(objs...)

	role := conformantRole()
	role.info.TrustPolicyDocument = `{"Statement":[{"Action":"sts:AssumeRoleWithWebIdentity","Effect":"Allow","Condition":{"StringEquals":{"oidc:sub":"system:serviceaccount:tenants-app1:tenant-runtime"}}}]}`
	role.info.InlinePolicyNames = nil

	findings, err := Audit(context.Background(), typed, conformantDyn(), role)
	if err != nil {
		t.Fatal(err)
	}
	got := types(findings)
	for _, want := range []cloud.PlatformFindingType{
		cloud.PlatformServiceAccountAnnotated,
		cloud.PlatformRoleTrustMismatch,
		cloud.PlatformRoleModelScopeMissing,
	} {
		if !got[want] {
			t.Errorf("expected %s on retired IRSA wiring, got %+v", want, got)
		}
	}
	// Inline policies are the contract, so their absence must not read as clean
	// and their presence must never be flagged wholesale.
	if got[cloud.PlatformRoleInlineUnexpected] {
		t.Error("a role with no inline policies must not be flagged for unexpected ones")
	}
}

// TestAudit_ConformantInlinePoliciesAreNotFlagged guards the direction of the
// inline check. The operator generates these five from the Platform spec; the
// old check flagged any inline policy at all, which fired on every tenant.
func TestAudit_ConformantInlinePoliciesAreNotFlagged(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	role := conformantRole()
	role.info.InlinePolicyNames = []string{
		"bedrock-model-scoping", "datastore-access", "capability-access",
		"tenant-secrets", "tenant-key-access",
	}

	findings, err := Audit(context.Background(), typed, conformantDyn(), role)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("the operator's own inline policies must not be findings, got %+v", findings)
	}
}

func TestAudit_HandAttachedInlinePolicy(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	role := conformantRole()
	role.info.InlinePolicyNames = append(role.info.InlinePolicyNames, "ops-hotfix-s3")

	findings, err := Audit(context.Background(), typed, conformantDyn(), role)
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformRoleInlineUnexpected] {
		t.Fatalf("expected TENANT_ROLE_INLINE_POLICY_UNEXPECTED for a hand-attached policy, got %+v", findings)
	}
	for _, f := range findings {
		if f.Type == cloud.PlatformRoleInlineUnexpected && !strings.Contains(f.Detail, "ops-hotfix-s3") {
			t.Errorf("finding must name the offending policy: %q", f.Detail)
		}
	}
}

// TestAudit_SuspendedRoleSkipsInlineChecks: the operator is observe-only under
// the kill-switch and writes no policy, so a suspended role's inline set is
// whatever the kill-switch left. Auditing it would report drift for the
// kill-switch doing its job.
func TestAudit_SuspendedRoleSkipsInlineChecks(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	cr := platformCR("Suspended", []string{"anthropic"})
	_ = unstructured.SetNestedField(cr.Object, "2026-07-25T00:00:00Z", "status", "suspendedAt")

	role := conformantRole()
	role.info.Tags = map[string]string{"platform.nanohype.dev/suspended": "true"}
	role.info.InlinePolicyNames = nil
	role.info.AttachedPolicyARNs = nil

	findings, err := Audit(context.Background(), typed, dynClient(cr, budgetCR(true), tenantCR(false, false)), role)
	if err != nil {
		t.Fatal(err)
	}
	got := types(findings)
	if got[cloud.PlatformRoleModelScopeMissing] {
		t.Error("must not demand the model-scoping policy on a suspended tenant")
	}
	if got[cloud.PlatformRoleNoBaseline] {
		t.Error("must not demand the baseline on a suspended tenant")
	}
}

func TestAudit_PodIdentityAssociationMissing(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	role := conformantRole()
	role.assoc = nil // nothing binds the ServiceAccount

	findings, err := Audit(context.Background(), typed, conformantDyn(), role)
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformPodIdentityMissing] {
		t.Fatalf("expected POD_IDENTITY_ASSOCIATION_MISSING, got %+v", findings)
	}
}

// TestAudit_PodIdentityAssociationMismatch is the finding the trust-policy check
// cannot make. Both roles have an identical, conformant trust document — under
// Pod Identity it carries no subject — so binding a tenant to a foreign role is
// only visible in the association.
func TestAudit_PodIdentityAssociationMismatch(t *testing.T) {
	const foreign = "arn:aws:iam::123456789012:role/dev-other-tenant"
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	role := conformantRole()
	role.assoc[tNS+"/"+defaultSAName] = &cloud.PodIdentityAssociation{
		RoleARN: foreign, Namespace: tNS, ServiceAccount: defaultSAName,
	}

	findings, err := Audit(context.Background(), typed, conformantDyn(), role)
	if err != nil {
		t.Fatal(err)
	}
	var mismatch *cloud.PlatformFinding
	for i, f := range findings {
		if f.Type == cloud.PlatformPodIdentityMismatch {
			mismatch = &findings[i]
		}
	}
	if mismatch == nil {
		t.Fatalf("expected POD_IDENTITY_ASSOCIATION_MISMATCH, got %+v", findings)
	}
	if mismatch.Severity != cloud.SeverityCritical {
		t.Errorf("a tenant bound to a foreign role is Critical, got %s", mismatch.Severity)
	}
	if !strings.Contains(mismatch.Detail, foreign) {
		t.Errorf("finding must name the foreign role: %q", mismatch.Detail)
	}
}

// TestAudit_VClusterWithoutPublishedBinding: under vcluster isolation the bound
// ServiceAccount is syncer-translated. Without the published binding the auditor
// must say so rather than look up tenant-runtime, which does not exist on the
// host and would read as a missing ServiceAccount on a conformant tenant.
func TestAudit_VClusterWithoutPublishedBinding(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	dyn := dynClient(vclusterPlatformCR(), budgetCR(true), tenantCR(false, false))

	findings, err := Audit(context.Background(), typed, dyn, conformantRole())
	if err != nil {
		t.Fatal(err)
	}
	got := types(findings)
	if !got[cloud.PlatformPodIdentityUnknown] {
		t.Errorf("expected POD_IDENTITY_BINDING_UNKNOWN, got %+v", got)
	}
	if got[cloud.PlatformServiceAccountMissing] {
		t.Error("must not report a missing ServiceAccount when the bound name is unknowable")
	}
}

// TestAudit_AssociationProbeFailureIsNotClean: a probe that could not run must
// not read as a verified binding.
func TestAudit_AssociationProbeFailureIsNotClean(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	role := conformantRole()
	role.assocErr = errors.New("AccessDenied")

	findings, err := Audit(context.Background(), typed, conformantDyn(), role)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("a failed association probe must not produce a clean report")
	}
	if !types(findings)[cloud.PlatformNotReady] {
		t.Errorf("expected the probe failure to surface, got %+v", findings)
	}
}

func TestAudit_BudgetMissing(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	// Platform references tBudget and tTen, but no BudgetPolicy/Tenant exist.
	findings, err := Audit(context.Background(), typed, dynClient(platformCR("Ready", []string{"anthropic"})), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := types(findings)
	if !got[cloud.PlatformBudgetMissing] {
		t.Errorf("expected BUDGET_POLICY_MISSING, got %+v", got)
	}
	if !got[cloud.PlatformTenantMissing] {
		t.Errorf("expected TENANT_MISSING, got %+v", got)
	}
}

func TestAudit_KillSwitchDisabled(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	// SOC2 platform whose BudgetPolicy has the kill-switch off; Tenant also SOC2.
	dyn := dynClient(platformCRCompliance(true, false), budgetCR(false), tenantCR(true, false))
	findings, err := Audit(context.Background(), typed, dyn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformKillSwitchDisabled] {
		t.Fatalf("expected KILL_SWITCH_DISABLED, got %+v", findings)
	}
}

// Every route resolves to a guardrail — its own, the gateway default, or the
// cluster baseline the operator reads from SSM. The baseline is the right
// default for a general workload, but a route reaches it by omission. These
// cases pin that a hipaa Platform has to have chosen.
func TestAudit_HipaaRouteInheritingBaselineIsAFinding(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	dyn := dynClient(platformCRCompliance(true, true), budgetCR(true), tenantCR(true, true))
	addGateways(t, dyn, gatewayCR("gw", tName, "", map[string]string{"review": ""}))
	findings, err := Audit(context.Background(), typed, dyn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformHipaaGuardrailInherited] {
		t.Fatalf("expected HIPAA_GUARDRAIL_INHERITED, got %+v", findings)
	}
}

func TestAudit_HipaaGuardrailSatisfiedByEitherRef(t *testing.T) {
	for _, tc := range []struct {
		name       string
		defaultRef string
		routes     map[string]string
	}{
		{"gateway default covers every route", "phi-guardrail", map[string]string{"review": "", "summarize": ""}},
		{"each route names its own", "", map[string]string{"review": "phi-guardrail", "summarize": "phi-guardrail"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			typed := kubefake.NewSimpleClientset(conformantObjects()...)
			dyn := dynClient(platformCRCompliance(true, true), budgetCR(true), tenantCR(true, true))
			addGateways(t, dyn, gatewayCR("gw", tName, tc.defaultRef, tc.routes))
			findings, err := Audit(context.Background(), typed, dyn, nil)
			if err != nil {
				t.Fatal(err)
			}
			if types(findings)[cloud.PlatformHipaaGuardrailInherited] {
				t.Fatalf("a named guardrail must satisfy the check, got %+v", findings)
			}
		})
	}
}

// The rule is scoped to hipaa. Inheriting the baseline is the intended default
// everywhere else, so flagging it generally would make the finding noise.
func TestAudit_NonHipaaRouteMayInheritBaseline(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	dyn := dynClient(platformCRCompliance(true, false), budgetCR(true), tenantCR(true, false))
	addGateways(t, dyn, gatewayCR("gw", tName, "", map[string]string{"review": ""}))
	findings, err := Audit(context.Background(), typed, dyn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if types(findings)[cloud.PlatformHipaaGuardrailInherited] {
		t.Fatalf("a non-hipaa platform may inherit the baseline, got %+v", findings)
	}
}

// A gateway in the same namespace owned by a different Platform. Without the
// platformRef filter this would report one Platform's route against another.
func TestAudit_HipaaIgnoresAnotherPlatformsGateway(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	dyn := dynClient(platformCRCompliance(true, true), budgetCR(true), tenantCR(true, true))
	addGateways(t, dyn,
		gatewayCR("gw-self", tName, "phi-guardrail", map[string]string{"review": ""}),
		gatewayCR("gw-other", "some-other-platform", "", map[string]string{"unguarded": ""}))
	findings, err := Audit(context.Background(), typed, dyn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if types(findings)[cloud.PlatformHipaaGuardrailInherited] {
		t.Fatalf("another Platform's gateway must not be attributed here, got %+v", findings)
	}
}

func TestAudit_ComplianceWeakerThanTenant(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	// Tenant requires SOC2; Platform does not set it.
	dyn := dynClient(platformCRCompliance(false, false), budgetCR(true), tenantCR(true, false))
	findings, err := Audit(context.Background(), typed, dyn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformComplianceWeaker] {
		t.Fatalf("expected COMPLIANCE_WEAKER_THAN_TENANT, got %+v", findings)
	}
}

// ciliumNetpolCR builds the tenant egress CiliumNetworkPolicy in the shape the
// operator's ensureCiliumEgress writes it: an endpointSelector matching the
// whole namespace, and the egress allow-list. spec.ingress is absent, which is
// what the operator emits for a tenant policy (denyIngress=false).
func ciliumNetpolCR(mutate func(spec map[string]interface{})) *unstructured.Unstructured {
	spec := map[string]interface{}{
		"endpointSelector": map[string]interface{}{"matchLabels": map[string]interface{}{}},
		"egress": []interface{}{
			map[string]interface{}{
				"toEntities": []interface{}{"host"},
				"toPorts": []interface{}{map[string]interface{}{"ports": []interface{}{
					map[string]interface{}{"port": "80", "protocol": "TCP"},
				}}},
			},
		},
	}
	if mutate != nil {
		mutate(spec)
	}
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   map[string]interface{}{"name": netpolName, "namespace": tNS},
		"spec":       spec,
	}}
	return u
}

// TestAuditNetworkPolicyCiliumEngine covers the tenant egress policy on a cilium
// cluster, where the operator emits a CiliumNetworkPolicy and NO vanilla
// NetworkPolicy exists. Every other fixture in this file seeds the vanilla kind,
// which models the `kubernetes` engine — a configuration the operator's chart
// does not default to and no cluster in the fleet runs.
func TestAuditNetworkPolicyCiliumEngine(t *testing.T) {
	tests := []struct {
		name    string
		cnp     *unstructured.Unstructured
		wantSev cloud.Severity
		wantTyp cloud.PlatformFindingType
		wantOK  bool // no findings at all
	}{
		{
			name:   "conformant cilium policy is clean",
			cnp:    ciliumNetpolCR(nil),
			wantOK: true,
		},
		{
			// An empty ingress list is cilium's default-deny form — strictly
			// stronger than omitting the key, so it must not read as a weakening.
			name:   "empty ingress list is default-deny, not a weakening",
			cnp:    ciliumNetpolCR(func(s map[string]interface{}) { s["ingress"] = []interface{}{} }),
			wantOK: true,
		},
		{
			name:    "no policy of either kind is missing containment",
			cnp:     nil,
			wantSev: cloud.SeverityCritical,
			wantTyp: cloud.PlatformNetworkPolicyMissing,
		},
		{
			name:    "no egress rules imposes no allow-list",
			cnp:     ciliumNetpolCR(func(s map[string]interface{}) { s["egress"] = []interface{}{} }),
			wantSev: cloud.SeverityHigh,
			wantTyp: cloud.PlatformNetworkPolicyWeak,
		},
		{
			name: "ingress rules break the egress-only contract",
			cnp: ciliumNetpolCR(func(s map[string]interface{}) {
				s["ingress"] = []interface{}{map[string]interface{}{"fromEntities": []interface{}{"all"}}}
			}),
			wantSev: cloud.SeverityHigh,
			wantTyp: cloud.PlatformNetworkPolicyWeak,
		},
		{
			name: "matchLabels narrows the policy to a subset of pods",
			cnp: ciliumNetpolCR(func(s map[string]interface{}) {
				s["endpointSelector"] = map[string]interface{}{
					"matchLabels": map[string]interface{}{"app": "only-me"},
				}
			}),
			wantSev: cloud.SeverityHigh,
			wantTyp: cloud.PlatformNetworkPolicyWeak,
		},
		{
			name: "matchExpressions narrows the policy just as matchLabels does",
			cnp: ciliumNetpolCR(func(s map[string]interface{}) {
				s["endpointSelector"] = map[string]interface{}{
					"matchExpressions": []interface{}{map[string]interface{}{
						"key": "app", "operator": "Exists",
					}},
				}
			}),
			wantSev: cloud.SeverityHigh,
			wantTyp: cloud.PlatformNetworkPolicyWeak,
		},
	}

	f := func(sev cloud.Severity, typ cloud.PlatformFindingType, resource, detail, remediation string) cloud.PlatformFinding {
		return cloud.PlatformFinding{Severity: sev, Type: typ, Resource: resource, Detail: detail}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// No vanilla NetworkPolicy anywhere: this is the cilium engine.
			typed := kubefake.NewSimpleClientset()
			var objs []runtime.Object
			if tc.cnp != nil {
				objs = append(objs, tc.cnp)
			}
			got := auditNetworkPolicy(context.Background(), typed, dynClient(objs...), tNS, f)

			if tc.wantOK {
				if len(got) != 0 {
					t.Fatalf("want no findings on a conformant cilium tenant, got %d: %+v", len(got), got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want exactly 1 finding, got %d: %+v", len(got), got)
			}
			if got[0].Type != tc.wantTyp || got[0].Severity != tc.wantSev {
				t.Errorf("got %s/%s, want %s/%s", got[0].Severity, got[0].Type, tc.wantSev, tc.wantTyp)
			}
		})
	}
}
