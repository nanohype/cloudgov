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
	tName = "app1"
	tNS   = "tenants-app1"
	tTen  = "acme"
	tPers = "eng"
	tRole = "arn:aws:iam::123456789012:role/dev-app1-tenant"
)

func platformCR(phase string, families []string) *unstructured.Unstructured {
	fam := make([]interface{}, len(families))
	for i, s := range families {
		fam[i] = s
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "agents.stxkxs.io/v1alpha1",
		"kind":       "Platform",
		"metadata":   map[string]interface{}{"name": tName, "namespace": "eks-agent-platform"},
		"spec": map[string]interface{}{
			"tenant":   tTen,
			"persona":  tPers,
			"identity": map[string]interface{}{"allowedModelFamilies": fam},
		},
		"status": map[string]interface{}{"phase": phase, "namespace": tNS, "iamRoleArn": tRole},
	}}
}

func dynClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{platformGVR: "PlatformList"},
		objs...,
	)
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

func TestAudit_Conformant(t *testing.T) {
	typed := kubefake.NewSimpleClientset(conformantObjects()...)
	findings, err := Audit(context.Background(), typed, dynClient(platformCR("Ready", []string{"anthropic"})))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("conformant platform should have 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestAudit_DriftDetected(t *testing.T) {
	// Namespace exists but PSS is wrong; NetworkPolicy and ServiceAccount are absent.
	typed := kubefake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tNS, Labels: map[string]string{
			platformLabel: tName, tenantLabel: tTen, personaLabel: tPers,
		}}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: defaultName, Namespace: tNS}},
		&corev1.LimitRange{ObjectMeta: metav1.ObjectMeta{Name: defaultName, Namespace: tNS}},
	)
	findings, err := Audit(context.Background(), typed, dynClient(platformCR("Ready", []string{"anthropic"})))
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
	typed := kubefake.NewSimpleClientset() // nothing provisioned
	findings, err := Audit(context.Background(), typed, dynClient(platformCR("Ready", []string{"anthropic"})))
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformNamespaceMissing] {
		t.Fatalf("expected NAMESPACE_MISSING, got %+v", findings)
	}
}

func TestAudit_NotReadySkipsResourceChecks(t *testing.T) {
	typed := kubefake.NewSimpleClientset() // nothing provisioned, but phase is Pending
	findings, err := Audit(context.Background(), typed, dynClient(platformCR("Pending", []string{"anthropic"})))
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
	// neither allowedModels nor allowedModelFamilies set
	findings, err := Audit(context.Background(), typed, dynClient(platformCR("Ready", nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !types(findings)[cloud.PlatformIdentityInvalid] {
		t.Fatalf("expected IDENTITY_INVALID when no models declared, got %+v", findings)
	}
}
