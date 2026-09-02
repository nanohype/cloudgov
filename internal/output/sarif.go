package output

import (
	"encoding/json"
	"io"
	"strings"
	"unicode"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compliance"
)

// SARIF 2.1.0 structures (minimal subset for GitHub Advanced Security).
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

// sarifInvocation carries what the scan could NOT read.
//
// SARIF's results array says what was found; it has no way to say that part of
// the account was unreadable, and a consumer cannot tell a clean account from an
// account half of which returned AccessDenied. That distinction is the guarantee
// this tool exists to make, and every other format carries it — the JSON writers
// take an incomplete list, the table renderer prints a note, and the process
// exits 3.
//
// SARIF is the one format that becomes a durable artifact: it is uploaded,
// ingested and read later by someone who never sees the exit code. Reporting a
// partial scan as a clean one there is the failure mode with the longest half
// life, so the run is marked unsuccessful and each unread probe is attached as a
// tool execution notification.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

// sarifInvocations renders the incomplete record. An empty list is a complete
// scan, and it is still emitted — an absent invocations array and a successful
// one are different claims, and only one of them is being made.
func sarifInvocations(incomplete []string) []sarifInvocation {
	notes := make([]sarifNotification, 0, len(incomplete))
	for _, entry := range incomplete {
		notes = append(notes, sarifNotification{
			Level:   "warning",
			Message: sarifMessage{Text: entry},
		})
	}
	return []sarifInvocation{{
		ExecutionSuccessful:        len(incomplete) == 0,
		ToolExecutionNotifications: notes,
	}}
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
	Kind    string       `json:"kind"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// WriteSARIF writes IAM findings in SARIF 2.1.0 format.
func WriteSARIF(w io.Writer, findings []cloud.Finding, version string, incomplete []string) error {
	rules := buildRules()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          rules,
			}},
			Invocations: sarifInvocations(incomplete),
			Results:     results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// WriteStorageSARIF writes storage audit findings in SARIF 2.1.0 format.
func WriteStorageSARIF(w io.Writer, findings []cloud.BucketFinding, version string, incomplete []string) error {
	rules := buildStorageRules()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          rules,
			}},
			Invocations: sarifInvocations(incomplete),
			Results:     results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// WriteSecretsSARIF writes secret findings in SARIF 2.1.0 format.
func WriteSecretsSARIF(w io.Writer, findings []cloud.SecretFinding, version string, incomplete []string) error {
	rules := buildSecretsRules()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          rules,
			}},
			Invocations: sarifInvocations(incomplete),
			Results:     results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifReport assembles a SARIF 2.1.0 log from a tool version, its rules, and
// results. Shared by the per-domain SARIF writers below.
func sarifReport(version string, rules []sarifRule, results []sarifResult, incomplete []string) sarifLog {
	return sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          rules,
			}},
			Invocations: sarifInvocations(incomplete),
			Results:     results,
		}},
	}
}

func encodeSARIF(w io.Writer, log sarifLog) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// WriteK8sSARIF writes Kubernetes RBAC findings in SARIF 2.1.0 format.
func WriteK8sSARIF(w io.Writer, findings []cloud.K8sFinding, version string, incomplete []string) error {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}
	return encodeSARIF(w, sarifReport(version, buildK8sRules(), results, incomplete))
}

func buildK8sRules() []sarifRule {
	types := []struct {
		id          cloud.K8sFindingType
		name, level string
	}{
		{cloud.K8sClusterAdmin, "ClusterAdmin", "error"},
		{cloud.K8sWildcardPermission, "WildcardPermission", "error"},
		{cloud.K8sBindingTooBroad, "BindingTooBroad", "error"},
		{cloud.K8sDangerousVerb, "DangerousVerb", "warning"},
	}
	rules := make([]sarifRule, 0, len(types))
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

// WriteLambdaSARIF writes Lambda resource-policy findings in SARIF 2.1.0 format.
func WriteLambdaSARIF(w io.Writer, findings []cloud.LambdaPolicyFinding, version string, incomplete []string) error {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}
	return encodeSARIF(w, sarifReport(version, buildLambdaRules(), results, incomplete))
}

func buildLambdaRules() []sarifRule {
	types := []struct {
		id          cloud.LambdaPolicyFindingType
		name, level string
	}{
		{cloud.LambdaPublicInvoke, "PublicInvoke", "error"},
		{cloud.LambdaCrossAccount, "CrossAccountInvoke", "error"},
		{cloud.LambdaConfusedDeputy, "ConfusedDeputyRisk", "warning"},
		{cloud.LambdaWildcardAction, "WildcardAction", "warning"},
	}
	rules := make([]sarifRule, 0, len(types))
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

// WriteComplianceSARIF writes failed and not-evaluated controls in SARIF 2.1.0
// format. Passing controls are omitted. Rule level follows each control's
// severity for failures, "note" for not-evaluated.
func WriteComplianceSARIF(w io.Writer, report compliance.ComplianceReport, version string, incomplete []string) error {
	var rules []sarifRule
	var results []sarifResult
	seen := make(map[string]bool)
	for _, r := range report.Results {
		if r.Status == compliance.StatusPass {
			continue
		}
		level := "note"
		if r.Status == compliance.StatusFail {
			level = sarifLevel(r.Control.Severity)
		}
		if !seen[r.Control.ID] {
			seen[r.Control.ID] = true
			rules = append(rules, sarifRule{
				ID:               r.Control.ID,
				Name:             r.Control.Title,
				ShortDescription: sarifMessage{Text: r.Control.Title},
				DefaultConfig:    sarifRuleConfig{Level: level},
			})
		}
		results = append(results, sarifResult{
			RuleID:  r.Control.ID,
			Level:   level,
			Message: sarifMessage{Text: r.Detail},
			Kind:    "open",
		})
	}
	return encodeSARIF(w, sarifReport(version, rules, results, incomplete))
}

// WriteDriftSARIF writes drifted resources (modified, deleted, or errored) in
// SARIF 2.1.0 format. In-sync resources are omitted.
func WriteDriftSARIF(w io.Writer, results []cloud.DriftResult, version string, incomplete []string) error {
	var out []sarifResult
	for _, r := range results {
		if r.Status == cloud.DriftInSync {
			continue
		}
		out = append(out, sarifResult{
			RuleID:  string(r.Status),
			Level:   driftLevel(r.Status),
			Message: sarifMessage{Text: r.ResourceName + ": " + r.Detail},
			Kind:    "open",
		})
	}
	return encodeSARIF(w, sarifReport(version, buildDriftRules(), out, incomplete))
}

func buildDriftRules() []sarifRule {
	types := []struct {
		id          cloud.DriftStatus
		name, level string
	}{
		{cloud.DriftModified, "Modified", "warning"},
		{cloud.DriftDeleted, "Deleted", "error"},
		{cloud.DriftError, "Error", "note"},
	}
	rules := make([]sarifRule, 0, len(types))
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

func driftLevel(s cloud.DriftStatus) string {
	switch s {
	case cloud.DriftDeleted:
		return "error"
	case cloud.DriftModified:
		return "warning"
	default:
		return "note"
	}
}

// WritePlatformSARIF writes Platform-tenant conformance findings in SARIF 2.1.0.
func WritePlatformSARIF(w io.Writer, findings []cloud.PlatformFinding, version string, incomplete []string) error {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Platform + ": " + f.Detail},
			Kind:    "open",
		})
	}
	return encodeSARIF(w, sarifReport(version, buildPlatformRules(), results, incomplete))
}

func buildPlatformRules() []sarifRule {
	types := []struct {
		id          cloud.PlatformFindingType
		name, level string
	}{
		{cloud.PlatformNamespaceMissing, "NamespaceMissing", "error"},
		{cloud.PlatformPSSNotRestricted, "PSSNotRestricted", "error"},
		{cloud.PlatformLabelMissing, "LabelMissing", "note"},
		{cloud.PlatformQuotaMissing, "ResourceQuotaMissing", "error"},
		{cloud.PlatformLimitRangeMissing, "LimitRangeMissing", "warning"},
		{cloud.PlatformNetworkPolicyMissing, "NetworkPolicyMissing", "error"},
		{cloud.PlatformNetworkPolicyWeak, "NetworkPolicyWeak", "error"},
		{cloud.PlatformServiceAccountMissing, "ServiceAccountMissing", "error"},
		{cloud.PlatformServiceAccountAnnotated, "ServiceAccountAnnotated", "warning"},
		{cloud.PlatformIdentityInvalid, "IdentityInvalid", "warning"},
		{cloud.PlatformNotReady, "NotReady", "note"},
		{cloud.PlatformRoleMissing, "TenantRoleMissing", "error"},
		{cloud.PlatformRoleTrustMismatch, "TenantRoleTrustMismatch", "error"},
		{cloud.PlatformRoleInlineUnexpected, "TenantRoleInlinePolicyUnexpected", "error"},
		{cloud.PlatformRoleModelScopeMissing, "TenantRoleModelScopingMissing", "error"},
		{cloud.PlatformRoleExtraPolicyMissing, "TenantRoleExtraPolicyMissing", "warning"},
		{cloud.PlatformRoleSuspensionDrift, "TenantRoleSuspensionDrift", "error"},
		{cloud.PlatformRoleNoBaseline, "TenantRoleNoBaseline", "error"},
		{cloud.PlatformPodIdentityMissing, "PodIdentityAssociationMissing", "error"},
		{cloud.PlatformPodIdentityMismatch, "PodIdentityAssociationMismatch", "error"},
		{cloud.PlatformPodIdentityUnknown, "PodIdentityBindingUnknown", "note"},
		{cloud.PlatformBudgetMissing, "BudgetPolicyMissing", "error"},
		{cloud.PlatformKillSwitchDisabled, "KillSwitchDisabled", "error"},
		{cloud.PlatformComplianceWeaker, "ComplianceWeakerThanTenant", "error"},
		{cloud.PlatformTenantMissing, "TenantMissing", "note"},
		{cloud.PlatformHipaaGuardrailInherited, "HipaaGuardrailInherited", "error"},
	}
	rules := make([]sarifRule, 0, len(types))
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

func sarifLevel(s cloud.Severity) string {
	switch s {
	case cloud.SeverityCritical, cloud.SeverityHigh:
		return "error"
	case cloud.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteCertsSARIF writes certificate-expiry findings in SARIF 2.1.0 format. The
// rule id is the cert status (EXPIRED, EXPIRING_7D, …); the level follows severity.
func WriteCertsSARIF(w io.Writer, findings []cloud.CertFinding, version string, incomplete []string) error {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Status),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}
	return encodeSARIF(w, sarifReport(version, buildCertRules(), results, incomplete))
}

func buildCertRules() []sarifRule {
	statuses := []struct {
		id          cloud.CertStatus
		name, level string
	}{
		{cloud.CertExpired, "Expired", "error"},
		{cloud.CertCritical, "Expiring7d", "error"},
		{cloud.CertHigh, "Expiring30d", "error"},
		{cloud.CertMedium, "Expiring60d", "warning"},
		{cloud.CertLow, "Expiring90d", "note"},
	}
	rules := make([]sarifRule, 0, len(statuses))
	for _, s := range statuses {
		rules = append(rules, sarifRule{
			ID:               string(s.id),
			Name:             s.name,
			ShortDescription: sarifMessage{Text: s.name},
			DefaultConfig:    sarifRuleConfig{Level: s.level},
		})
	}
	return rules
}

func buildStorageRules() []sarifRule {
	types := []struct {
		id    cloud.BucketFindingType
		name  string
		level string
	}{
		{cloud.BucketPublicAccess, "PublicAccess", "error"},
		{cloud.BucketUnencrypted, "Unencrypted", "error"},
		{cloud.BucketNoVersioning, "NoVersioning", "warning"},
		{cloud.BucketNoLogging, "NoLogging", "note"},
		{cloud.BucketPublicACL, "PublicACL", "error"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

func buildSecretsRules() []sarifRule {
	types := []struct {
		id    cloud.SecretFindingType
		name  string
		level string
	}{
		{cloud.SecretAWSAccessKey, "AWSAccessKey", "error"},
		{cloud.SecretGCPServiceAccountKey, "GCPServiceAccountKey", "error"},
		{cloud.SecretPrivateKey, "PrivateKey", "error"},
		{cloud.SecretAzureConnectionString, "AzureConnectionString", "error"},
		{cloud.SecretPassword, "Password", "error"},
		{cloud.SecretAPIKey, "APIKey", "error"},
		{cloud.SecretBearerToken, "BearerToken", "error"},
		{cloud.SecretGenericSecret, "GenericSecret", "warning"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

// buildTagRules and buildOrphanRules give the two domains with no standalone
// SARIF writer the rule entries the audit report needs.
//
// A SARIF result whose ruleId is not declared in the driver's rule table is
// dropped by some consumers and rendered without a name by others, so a domain
// cannot be added to the results without being added here.
func buildTagRules() []sarifRule {
	return []sarifRule{{
		ID:               tagRuleID,
		Name:             "MissingRequiredTags",
		ShortDescription: sarifMessage{Text: "Resource is missing one or more required tags"},
		DefaultConfig:    sarifRuleConfig{Level: "warning"},
	}}
}

// camelCase turns an OrphanKind's snake_case id into a SARIF rule name.
func camelCase(id string) string {
	var b strings.Builder
	upper := true
	for _, r := range id {
		if r == '_' {
			upper = true
			continue
		}
		if upper {
			b.WriteRune(unicode.ToUpper(r))
			upper = false
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// tagRuleID is the single rule every tag finding reports under. Tag findings do
// not carry a type — the finding IS "these keys are absent" — so the missing
// keys travel in the message rather than in the rule.
const tagRuleID = "MISSING_REQUIRED_TAGS"

func buildOrphanRules() []sarifRule {
	rules := make([]sarifRule, 0, len(cloud.AllOrphanKinds))
	for _, kind := range cloud.AllOrphanKinds {
		rules = append(rules, sarifRule{
			ID:               string(kind),
			Name:             "Orphan" + camelCase(string(kind)),
			ShortDescription: sarifMessage{Text: "Unused resource still incurring cost"},
			DefaultConfig:    sarifRuleConfig{Level: "note"},
		})
	}
	return rules
}

// WriteAuditSARIF renders a full audit report as SARIF.
//
// Every domain the Report declares is rendered, because the exit code and the
// artifact are two halves of one answer to a merge gate. A writer covering a
// subset makes them disagree silently: the run exits 2 on a critical expired
// certificate and the file uploaded to code scanning contains no such result,
// and the artifact is the half a reviewer looks at.
//
// TestAuditSARIFCoversEveryDomain counts the Report's own finding slices by
// reflection, so a domain added there and not here fails the build rather than
// silently vanishing from the upload.
func WriteAuditSARIF(w io.Writer, report *audit.Report, version string, incomplete []string) error {
	var allRules []sarifRule
	allRules = append(allRules, buildRules()...)
	allRules = append(allRules, buildStorageRules()...)
	allRules = append(allRules, buildSecretsRules()...)
	allRules = append(allRules, buildNetworkRules()...)
	allRules = append(allRules, buildCertRules()...)
	allRules = append(allRules, buildTagRules()...)
	allRules = append(allRules, buildOrphanRules()...)

	var results []sarifResult
	for _, f := range report.IAM {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[iam] " + f.Detail},
			Kind:    "open",
		})
	}
	for _, f := range report.Storage {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[storage] " + f.Detail},
			Kind:    "open",
		})
	}
	for _, f := range report.Network {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[network] " + f.Detail},
			Kind:    "open",
		})
	}
	for _, f := range report.Secrets {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[secrets] " + f.Detail},
			Kind:    "open",
		})
	}
	for _, f := range report.Certs {
		results = append(results, sarifResult{
			RuleID:  string(f.Status),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[certs] " + f.Domain + ": " + f.Detail},
			Kind:    "open",
		})
	}
	for _, f := range report.Tags {
		results = append(results, sarifResult{
			RuleID:  tagRuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[tags] " + f.ResourceID + ": missing " + strings.Join(f.MissingTags, ", ")},
			Kind:    "open",
		})
	}
	// An orphan carries a cost rather than a severity, and the audit summary
	// counts it at LOW. Rendering it at the same level keeps the artifact and the
	// counts telling one story.
	for _, o := range report.Orphans {
		results = append(results, sarifResult{
			RuleID:  string(o.Kind),
			Level:   sarifLevel(cloud.SeverityLow),
			Message: sarifMessage{Text: "[orphans] " + o.ID + ": " + o.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          allRules,
			}},
			Invocations: sarifInvocations(incomplete),
			Results:     results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func buildNetworkRules() []sarifRule {
	types := []struct {
		id    cloud.NetworkFindingType
		name  string
		level string
	}{
		{cloud.NetworkOpenIngress, "OpenIngress", "error"},
		{cloud.NetworkOpenEgress, "OpenEgress", "warning"},
		{cloud.NetworkAdminPortOpen, "AdminPortOpen", "error"},
		{cloud.NetworkWideCIDR, "WideCIDR", "warning"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

func buildRules() []sarifRule {
	types := []struct {
		id    cloud.FindingType
		name  string
		level string
	}{
		{cloud.FindingAdminAccess, "AdminAccess", "error"},
		{cloud.FindingWildcardResource, "WildcardResource", "error"},
		{cloud.FindingUnusedPermission, "UnusedPermission", "error"},
		{cloud.FindingCrossAccountAccess, "CrossAccountAccess", "error"},
		{cloud.FindingStalePrincipal, "StalePrincipal", "warning"},
		{cloud.FindingBroadScope, "BroadScope", "warning"},
		{cloud.FindingPublicAccess, "PublicAccess", "error"},
		{cloud.FindingUnencrypted, "Unencrypted", "error"},
		{cloud.FindingNoVersioning, "NoVersioning", "warning"},
		{cloud.FindingOrphanResource, "OrphanResource", "note"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}
