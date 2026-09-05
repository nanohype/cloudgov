package aws

import (
	"context"
	"errors"
	"net/url"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	testTenantRole    = "production-cluster-digest-pipeline-tenant"
	testTenantRoleARN = "arn:aws:iam::111111111111:role/eks-agent-platform/tenants/" + testTenantRole
	testBoundaryARN   = "arn:aws:iam::111111111111:policy/tenant-permissions-boundary"
	testPodTrust      = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}]}`
)

func TestGetRoleInfo(t *testing.T) {
	// IAM returns the trust document URL-encoded; the auditor matches substrings
	// against it, so decoding is load-bearing rather than cosmetic.
	m := &mockIAM{
		roleDetail: map[string]iamtypes.Role{
			testTenantRole: {
				Arn:                      awssdk.String(testTenantRoleARN),
				AssumeRolePolicyDocument: awssdk.String(url.QueryEscape(testPodTrust)),
				Tags: []iamtypes.Tag{
					{Key: awssdk.String("platform.nanohype.dev/suspended"), Value: awssdk.String("true")},
				},
				PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
					PermissionsBoundaryArn: awssdk.String(testBoundaryARN),
				},
			},
		},
		attachedRole: map[string][][]iamtypes.AttachedPolicy{
			testTenantRole: {{{PolicyArn: awssdk.String("arn:aws:iam::111111111111:policy/baseline")}}},
		},
		inlineRole: map[string][][]string{
			testTenantRole: {{"bedrock-model-scoping", "datastore-access"}},
		},
	}
	p := &Provider{iam: m}

	info, err := p.GetRoleInfo(context.Background(), testTenantRole)
	if err != nil {
		t.Fatalf("GetRoleInfo: %v", err)
	}
	if info == nil {
		t.Fatal("expected role info")
	}
	if info.ARN != testTenantRoleARN {
		t.Errorf("ARN: got %q", info.ARN)
	}
	if info.TrustPolicyDocument != testPodTrust {
		t.Errorf("trust policy not URL-decoded:\n got %s\nwant %s", info.TrustPolicyDocument, testPodTrust)
	}
	if info.Tags["platform.nanohype.dev/suspended"] != "true" {
		t.Errorf("suspension tag: got %q", info.Tags["platform.nanohype.dev/suspended"])
	}
	if len(info.AttachedPolicyARNs) != 1 {
		t.Errorf("attached policies: got %v", info.AttachedPolicyARNs)
	}
	if len(info.InlinePolicyNames) != 2 {
		t.Errorf("inline policies: got %v", info.InlinePolicyNames)
	}
	// The auditor compares this ARN against the one the Platform publishes, so a
	// field that is read and dropped here reports every tenant's ceiling as
	// absent.
	if info.PermissionsBoundaryARN != testBoundaryARN {
		t.Errorf("permissions boundary: got %q, want %q", info.PermissionsBoundaryARN, testBoundaryARN)
	}
}

// A role with no boundary and a role whose boundary could not be read are the
// same value here, so the distinction has to hold somewhere: GetRole returns the
// field on every role and omits it only when there is none, and the whole call
// fails otherwise. An empty string is therefore an answer, and the auditor treats
// it as one.
func TestGetRoleInfo_NoBoundaryIsEmptyNotAnError(t *testing.T) {
	m := &mockIAM{
		roleDetail: map[string]iamtypes.Role{
			testTenantRole: {Arn: awssdk.String(testTenantRoleARN)},
		},
		attachedRole: map[string][][]iamtypes.AttachedPolicy{testTenantRole: {{}}},
		inlineRole:   map[string][][]string{testTenantRole: {{}}},
	}
	p := &Provider{iam: m}

	info, err := p.GetRoleInfo(context.Background(), testTenantRole)
	if err != nil {
		t.Fatalf("GetRoleInfo: %v", err)
	}
	if info == nil {
		t.Fatal("expected role info")
	}
	if info.PermissionsBoundaryARN != "" {
		t.Errorf("permissions boundary: got %q, want empty", info.PermissionsBoundaryARN)
	}
}

func TestGetRoleInfo_MissingRoleIsNotAnError(t *testing.T) {
	// The auditor distinguishes "role does not exist" (a Critical finding) from
	// "could not read the role" (an informational one), so a NoSuchEntity must
	// come back as (nil, nil) rather than an error.
	p := &Provider{iam: &mockIAM{}}

	info, err := p.GetRoleInfo(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("a missing role must not error: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil info for a missing role, got %+v", info)
	}
}

func TestGetPodIdentityAssociation(t *testing.T) {
	const ns, sa = "tenants-digest-pipeline", "tenant-runtime"
	p := &Provider{eks: mockEKS{associations: map[string]string{
		ns + "/" + sa: testTenantRoleARN,
	}}}

	assoc, err := p.GetPodIdentityAssociation(context.Background(), "production-cluster", ns, sa)
	if err != nil {
		t.Fatalf("GetPodIdentityAssociation: %v", err)
	}
	if assoc == nil {
		t.Fatal("expected an association")
	}
	// The list summary carries no role ARN — only Describe does — so a populated
	// RoleARN proves both calls ran.
	if assoc.RoleARN != testTenantRoleARN {
		t.Errorf("role: got %q want %q", assoc.RoleARN, testTenantRoleARN)
	}
	if assoc.Namespace != ns || assoc.ServiceAccount != sa {
		t.Errorf("binding: got %s/%s want %s/%s", assoc.Namespace, assoc.ServiceAccount, ns, sa)
	}
	if assoc.ARN == "" {
		t.Error("association ARN not populated")
	}
}

func TestGetPodIdentityAssociation_NoneIsNotAnError(t *testing.T) {
	// An unbound ServiceAccount is a High finding the auditor raises itself; the
	// provider reports absence, not failure.
	p := &Provider{eks: mockEKS{associations: map[string]string{}}}

	assoc, err := p.GetPodIdentityAssociation(context.Background(), "production-cluster", "tenants-x", "tenant-runtime")
	if err != nil {
		t.Fatalf("an unbound ServiceAccount must not error: %v", err)
	}
	if assoc != nil {
		t.Errorf("expected nil association, got %+v", assoc)
	}
}

func TestGetPodIdentityAssociation_ErrorsSurface(t *testing.T) {
	// The opposite of the case above: a probe that could not run must NOT read as
	// "no association". The auditor turns an error into an informational finding
	// rather than a clean result, so it has to reach the auditor.
	boom := errors.New("AccessDenied")

	if _, err := (&Provider{eks: mockEKS{listErr: boom}}).
		GetPodIdentityAssociation(context.Background(), "c", "ns", "sa"); err == nil {
		t.Error("a failed list must surface as an error, not as no association")
	}

	p := &Provider{eks: mockEKS{
		associations: map[string]string{"ns/sa": testTenantRoleARN},
		describeErr:  boom,
	}}
	if _, err := p.GetPodIdentityAssociation(context.Background(), "c", "ns", "sa"); err == nil {
		t.Error("a failed describe must surface as an error")
	}
}
