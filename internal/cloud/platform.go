package cloud

// PlatformFindingType classifies a conformance gap between a nanohype Platform
// tenant's declared contract and its live cluster/cloud state.
type PlatformFindingType string

const (
	PlatformNamespaceMissing      PlatformFindingType = "NAMESPACE_MISSING"
	PlatformPSSNotRestricted      PlatformFindingType = "PSS_NOT_RESTRICTED"
	PlatformLabelMissing          PlatformFindingType = "LABEL_MISSING"
	PlatformQuotaMissing          PlatformFindingType = "RESOURCE_QUOTA_MISSING"
	PlatformLimitRangeMissing     PlatformFindingType = "LIMIT_RANGE_MISSING"
	PlatformNetworkPolicyMissing  PlatformFindingType = "NETWORK_POLICY_MISSING"
	PlatformNetworkPolicyWeak     PlatformFindingType = "NETWORK_POLICY_WEAK"
	PlatformServiceAccountMissing PlatformFindingType = "SERVICE_ACCOUNT_MISSING"
	// PlatformServiceAccountAnnotated fires on the presence of a role-arn
	// annotation, not its absence. The tenant contract forbids the annotation;
	// the Pod Identity association is the binding.
	PlatformServiceAccountAnnotated PlatformFindingType = "SERVICE_ACCOUNT_ANNOTATED"
	PlatformIdentityInvalid         PlatformFindingType = "IDENTITY_INVALID"
	PlatformNotReady                PlatformFindingType = "NOT_READY"

	// AWS-side tenant role conformance.
	PlatformRoleMissing            PlatformFindingType = "TENANT_ROLE_MISSING"
	PlatformRoleTrustMismatch      PlatformFindingType = "TENANT_ROLE_TRUST_MISMATCH"
	PlatformRoleInlineUnexpected   PlatformFindingType = "TENANT_ROLE_INLINE_POLICY_UNEXPECTED"
	PlatformRoleModelScopeMissing  PlatformFindingType = "TENANT_ROLE_MODEL_SCOPING_MISSING"
	PlatformRoleExtraPolicyMissing PlatformFindingType = "TENANT_ROLE_EXTRA_POLICY_MISSING"
	PlatformRoleSuspensionDrift    PlatformFindingType = "TENANT_ROLE_SUSPENSION_DRIFT"
	PlatformRoleNoBaseline         PlatformFindingType = "TENANT_ROLE_NO_BASELINE"

	// EKS Pod Identity binding conformance. The association is what actually
	// vends the tenant role to tenant pods — the role's trust policy carries no
	// subject, so the binding is only observable here.
	PlatformPodIdentityMissing  PlatformFindingType = "POD_IDENTITY_ASSOCIATION_MISSING"
	PlatformPodIdentityMismatch PlatformFindingType = "POD_IDENTITY_ASSOCIATION_MISMATCH"
	PlatformPodIdentityUnknown  PlatformFindingType = "POD_IDENTITY_BINDING_UNKNOWN"

	// Budget + compliance cross-references.
	PlatformBudgetMissing      PlatformFindingType = "BUDGET_POLICY_MISSING"
	PlatformKillSwitchDisabled PlatformFindingType = "KILL_SWITCH_DISABLED"
	PlatformComplianceWeaker   PlatformFindingType = "COMPLIANCE_WEAKER_THAN_TENANT"
	PlatformTenantMissing      PlatformFindingType = "TENANT_MISSING"

	// A hipaa Platform whose model routes fall back to the cluster baseline
	// guardrail instead of naming one of their own.
	PlatformHipaaGuardrailInherited PlatformFindingType = "HIPAA_GUARDRAIL_INHERITED"
)

// AllPlatformFindingTypes is every type the platform auditor can emit. SARIF
// declares one rule per finding type and takes the ruleId straight from the
// type, so a type with no rule produces a result referencing a rule that is not
// declared in the run — invalid SARIF that most consumers drop silently. This
// list is what the rule table is checked against.
var AllPlatformFindingTypes = []PlatformFindingType{
	PlatformNamespaceMissing,
	PlatformPSSNotRestricted,
	PlatformLabelMissing,
	PlatformQuotaMissing,
	PlatformLimitRangeMissing,
	PlatformNetworkPolicyMissing,
	PlatformNetworkPolicyWeak,
	PlatformServiceAccountMissing,
	PlatformServiceAccountAnnotated,
	PlatformIdentityInvalid,
	PlatformNotReady,
	PlatformRoleMissing,
	PlatformRoleTrustMismatch,
	PlatformRoleInlineUnexpected,
	PlatformRoleModelScopeMissing,
	PlatformRoleExtraPolicyMissing,
	PlatformRoleSuspensionDrift,
	PlatformRoleNoBaseline,
	PlatformPodIdentityMissing,
	PlatformPodIdentityMismatch,
	PlatformPodIdentityUnknown,
	PlatformBudgetMissing,
	PlatformKillSwitchDisabled,
	PlatformComplianceWeaker,
	PlatformTenantMissing,
	PlatformHipaaGuardrailInherited,
}

// IAMRoleInfo is the read-only view of an IAM role the platform auditor needs to
// verify tenant-role conformance.
type IAMRoleInfo struct {
	ARN                 string
	TrustPolicyDocument string // URL-decoded JSON
	Tags                map[string]string
	AttachedPolicyARNs  []string
	InlinePolicyNames   []string
}

// PodIdentityAssociation is the read-only view of an EKS Pod Identity
// association: the (namespace, serviceAccount) → role binding that vends
// credentials to tenant pods. Under Pod Identity this is where the tenancy
// constraint lives — the role's trust policy has no subject — so it is the only
// place the binding can be verified.
type PodIdentityAssociation struct {
	ARN            string
	RoleARN        string
	Namespace      string
	ServiceAccount string
}

// PlatformFinding is a single conformance gap for a Platform tenant — the
// difference between what the eks-agent-platform contract requires and what is
// actually deployed. cloudgov only reports these (the operator enforces).
type PlatformFinding struct {
	Severity    Severity            `json:"severity"`
	Type        PlatformFindingType `json:"type"`
	Platform    string              `json:"platform"`
	Tenant      string              `json:"tenant,omitempty"`
	Namespace   string              `json:"namespace,omitempty"`
	Resource    string              `json:"resource,omitempty"` // the specific k8s/AWS object, when applicable
	Detail      string              `json:"detail"`
	Remediation string              `json:"remediation"`
}
