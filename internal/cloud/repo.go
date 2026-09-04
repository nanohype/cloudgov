package cloud

// Repository-settings governance.
//
// Branch protection, required checks and Dependabot state live only in GitHub.
// No gate inside a repo can observe them — a repo can have a green CI matrix, a
// protection rule that requires none of it, and nothing anywhere will say so.
// That is exactly what happened: three repos carried a protection rule with zero
// required checks (landing-zone among them, whose merges become live AWS
// infrastructure), ten had no protection at all, and every org-level default for
// new repositories was off, so repo N+1 started unprotected on both axes.
//
// These are reported, never enforced. cloudgov reads; a human or a deliberate
// apply changes settings.

// RepoFindingType names a single class of repository-settings gap.
type RepoFindingType string

const (
	// RepoNoProtection — the default branch has no protection rule at all.
	RepoNoProtection RepoFindingType = "NO_BRANCH_PROTECTION"
	// RepoNoRequiredChecks — a protection rule exists and requires no status
	// check. The most misleading state of the three: the repo reads as protected
	// in every UI and admits a PR whose entire CI matrix is red.
	RepoNoRequiredChecks RepoFindingType = "NO_REQUIRED_CHECKS"
	// RepoMissingRequiredCheck — an expected check is absent from the required set.
	RepoMissingRequiredCheck RepoFindingType = "MISSING_REQUIRED_CHECK"
	// RepoAdminsExempt — enforce_admins is off, so an admin merges past every
	// required check.
	RepoAdminsExempt RepoFindingType = "ADMINS_EXEMPT"
	// RepoForcePushAllowed — history on the default branch can be rewritten.
	RepoForcePushAllowed RepoFindingType = "FORCE_PUSH_ALLOWED"
	// RepoDeletionAllowed — the default branch can be deleted.
	RepoDeletionAllowed RepoFindingType = "BRANCH_DELETION_ALLOWED"
	// RepoAlertsDisabled — Dependabot vulnerability alerts are off, so an
	// advisory against this dependency tree is reported to nobody.
	RepoAlertsDisabled RepoFindingType = "DEPENDABOT_ALERTS_DISABLED"
	// RepoSecurityUpdatesDisabled — alerts are on but no remediation PR ever
	// opens by itself, so every patchable CVE waits on a human noticing.
	RepoSecurityUpdatesDisabled RepoFindingType = "DEPENDABOT_SECURITY_UPDATES_DISABLED"
	// RepoOpenAlerts — Dependabot alerts are open and unread.
	RepoOpenAlerts RepoFindingType = "DEPENDABOT_ALERTS_OPEN"
	// RepoUnprotectable — protection is unavailable on this repo's plan. Not a
	// misconfiguration and not fixable by any setting: a private repo on the free
	// plan cannot be protected at all. Reported so the exposure is stated rather
	// than mistaken for compliance.
	RepoUnprotectable RepoFindingType = "PROTECTION_UNAVAILABLE_ON_PLAN"
)

// RepoFindingTypes is every type this auditor can emit.
//
// Kept beside the constants, and checked against them:
// TestEveryFindingTypeListHoldsEveryConstantOfItsType fails the build when a
// constant is declared without joining the list, or when the list names one that
// no longer exists.
//
// Nothing renders repo findings as SARIF, so this list feeds nothing. The
// sibling that does feed a rule table is AllOrphanKinds, which internal/output
// iterates to build one; AllPlatformFindingTypes is only checked against a rule
// table written by hand beside it. This is the enumeration a renderer would be
// built from on the day one is written.
var RepoFindingTypes = []RepoFindingType{
	RepoNoProtection,
	RepoNoRequiredChecks,
	RepoMissingRequiredCheck,
	RepoAdminsExempt,
	RepoForcePushAllowed,
	RepoDeletionAllowed,
	RepoAlertsDisabled,
	RepoSecurityUpdatesDisabled,
	RepoOpenAlerts,
	RepoUnprotectable,
}

// RepoFinding is one gap between the committed expected settings and what
// GitHub reports.
type RepoFinding struct {
	Severity    Severity        `json:"severity"`
	Type        RepoFindingType `json:"type"`
	Repo        string          `json:"repo"`
	Detail      string          `json:"detail"`
	Remediation string          `json:"remediation"`
}

// RepoSettings is the observed state of one repository, as read from GitHub.
//
// Absent protection and empty protection are different facts and are kept
// distinguishable: Protected reports whether a rule exists at all, and
// RequiredChecks is meaningful only when it does. Collapsing them is how "no
// required checks" reads as "not protected" and gets fixed the wrong way.
type RepoSettings struct {
	Name       string `json:"name"`
	Private    bool   `json:"private"`
	Archived   bool   `json:"archived"`
	DefaultRef string `json:"defaultRef"`

	// Protected is false when the default branch carries no protection rule.
	Protected bool `json:"protected"`
	// ProtectionUnavailable is true when the API refused because the plan does
	// not offer protection for this repository. Distinct from Protected=false,
	// which is a choice.
	ProtectionUnavailable bool `json:"protectionUnavailable"`

	RequiredChecks   []string `json:"requiredChecks"`
	StrictChecks     bool     `json:"strictChecks"`
	EnforceAdmins    bool     `json:"enforceAdmins"`
	AllowForcePushes bool     `json:"allowForcePushes"`
	AllowDeletions   bool     `json:"allowDeletions"`

	AlertsEnabled          bool `json:"alertsEnabled"`
	SecurityUpdatesEnabled bool `json:"securityUpdatesEnabled"`
	OpenAlerts             int  `json:"openAlerts"`

	// Unread names the probes that did not answer, each with what the tool said.
	//
	// Every boolean above has a false that means "off" and, without this, a false
	// that means "the read failed". The GitHub API returns an error for an
	// unreachable endpoint, an unauthenticated CLI, a rate limit and a repository
	// genuinely lacking the feature alike, so treating a failed probe as "off"
	// files an outage as a governance breach — and the caller cannot tell.
	//
	// A probe that lands here is reported as an incomplete observation rather
	// than as a finding. An empty map means every probe answered.
	Unread map[string]string `json:"unread,omitempty"`
}

// MarkUnread records that one probe did not answer.
func (s *RepoSettings) MarkUnread(probe string, err error) {
	if s.Unread == nil {
		s.Unread = map[string]string{}
	}
	s.Unread[probe] = err.Error()
}
