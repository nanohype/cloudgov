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
	PlatformIRSAAnnotationMissing PlatformFindingType = "IRSA_ANNOTATION_MISSING"
	PlatformIRSARoleMismatch      PlatformFindingType = "IRSA_ROLE_MISMATCH"
	PlatformIdentityInvalid       PlatformFindingType = "IDENTITY_INVALID"
	PlatformNotReady              PlatformFindingType = "NOT_READY"
)

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
