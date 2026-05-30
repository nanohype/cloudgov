package platform

import (
	"context"
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
	tName   = "app1"
	tNS     = "tenants-app1"
	tMgmtNS = "eks-agent-platform"
	tTen    = "acme"
	tPers   = "eng"
	tBudget = "tenant-budget"
	tRole   = "arn:aws:iam::123456789012:role/dev-app1-tenant"
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
		"status": map[string]interface{}{"phase": phase, "namespace": tNS, "iamRoleArn": tRole},
	}}
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

func dynClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			platformGVR: "PlatformList",
			budgetGVR:   "BudgetPolicyList",
			tenantGVR:   "TenantList",
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
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
			Name: saName, Namespace: tNS, Annotations: map[string]string{irsaAnnotation: tRole},
		}},
	}
}

type fakeRoles struct {
	info *cloud.IAMRoleInfo
	err  error
}

func (f fakeRoles) GetRoleInfo(context.Context, string) (*cloud.IAMRoleInfo, error) {
	return f.info, f.err
}

func conformantRole() fakeRoles {
	return fakeRoles{info: &cloud.IAMRoleInfo{
		ARN:                 tRole,
		TrustPolicyDocument: `{"Condition":{"StringEquals":{"oidc:sub":"system:serviceaccount:tenants-app1:tenant-runtime"}}}`,
		Tags:                map[string]string{},
		AttachedPolicyARNs:  []string{"arn:aws:iam::123456789012:policy/tenant-baseline"},
	}}
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

func TestAudit_IRSARoleMissing(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	findings, err := Audit(context.Background(), typed, conformantDyn(), fakeRoles{info: nil})
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformIRSARoleMissing] {
		t.Fatalf("expected IRSA_ROLE_MISSING when the role is absent, got %+v", findings)
	}
}

func TestAudit_IRSADrift(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	role := fakeRoles{info: &cloud.IAMRoleInfo{
		ARN:                 tRole,
		TrustPolicyDocument: `{"Condition":{"StringEquals":{"oidc:sub":"system:serviceaccount:other-ns:other-sa"}}}`,
		Tags:                map[string]string{},
		InlinePolicyNames:   []string{"legacy-inline"},
	}}
	findings, err := Audit(context.Background(), typed, conformantDyn(), role)
	if err != nil {
		t.Fatal(err)
	}
	got := types(findings)
	for _, want := range []cloud.PlatformFindingType{
		cloud.PlatformIRSAInlinePolicy,
		cloud.PlatformIRSATrustMismatch,
		cloud.PlatformIRSANoBaseline,
	} {
		if !got[want] {
			t.Errorf("expected %s, got %+v", want, got)
		}
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
