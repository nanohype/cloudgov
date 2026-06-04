package compare

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// NormalizedFinding is a uniform representation of any finding type for comparison.
type NormalizedFinding struct {
	Domain     string `json:"domain"`
	Provider   string `json:"provider"`
	Type       string `json:"type"`
	ResourceID string `json:"resource_id"`
	Detail     string `json:"detail"`
	Severity   string `json:"severity"`
}

// MatchKey returns a string key for matching findings across reports.
// Severity is excluded so reclassified findings still match.
func (f NormalizedFinding) MatchKey() string {
	return f.Provider + "|" + f.Type + "|" + f.ResourceID + "|" + f.Detail
}

// ReportType identifies the kind of report.
type ReportType string

const (
	ReportTypeAudit   ReportType = "audit"
	ReportTypeCost    ReportType = "cost"
	ReportTypeIAM     ReportType = "iam"
	ReportTypeOrphans ReportType = "orphans"
	ReportTypeStorage ReportType = "storage"
	ReportTypeNetwork ReportType = "network"
	ReportTypeCerts   ReportType = "certs"
	ReportTypeTags    ReportType = "tags"
	ReportTypeSecrets ReportType = "secrets"
	ReportTypeQuotas  ReportType = "quotas"
	ReportTypeDrift   ReportType = "drift"
	ReportTypeUnknown ReportType = "unknown"
)

// DetectType examines JSON data and returns the report type.
func DetectType(data []byte) ReportType {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return ReportTypeUnknown
	}

	// Audit reports have "summary" + "duration"
	if _, hasSummary := raw["summary"]; hasSummary {
		if _, hasDuration := raw["duration"]; hasDuration {
			return ReportTypeAudit
		}
	}

	// Cost reports have "diffs"
	if _, hasDiffs := raw["diffs"]; hasDiffs {
		return ReportTypeCost
	}

	// IAM reports have "principals_scanned"
	if _, hasPrincipals := raw["principals_scanned"]; hasPrincipals {
		return ReportTypeIAM
	}

	// Orphans reports have "resources" + "estimated_monthly_usd"
	if _, hasResources := raw["resources"]; hasResources {
		if _, hasUSD := raw["estimated_monthly_usd"]; hasUSD {
			return ReportTypeOrphans
		}
	}

	// Quota reports have "quotas"
	if _, hasQuotas := raw["quotas"]; hasQuotas {
		return ReportTypeQuotas
	}

	// Drift reports have "results" (DriftResult list)
	if _, hasResults := raw["results"]; hasResults {
		return ReportTypeDrift
	}

	// Findings-based reports: peek at first finding element
	if findingsRaw, ok := raw["findings"]; ok {
		return detectFindingsType(findingsRaw)
	}

	return ReportTypeUnknown
}

func detectFindingsType(data json.RawMessage) ReportType {
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(data, &findings); err != nil || len(findings) == 0 {
		return ReportTypeUnknown
	}

	// Build a case-insensitive key set from the first element.
	// Go types without json tags serialize with PascalCase keys,
	// but we want to detect regardless of casing.
	first := make(map[string]bool, len(findings[0]))
	for k := range findings[0] {
		first[strings.ToLower(k)] = true
	}

	// Storage: has "bucket"
	if first["bucket"] {
		return ReportTypeStorage
	}
	// Network: has "protocol" and "port"
	if first["protocol"] && first["port"] {
		return ReportTypeNetwork
	}
	// Certs: has "expires_at" or "expiresat" and "days_left" or "daysleft"
	if (first["expires_at"] || first["expiresat"]) && (first["days_left"] || first["daysleft"]) {
		return ReportTypeCerts
	}
	// Tags: has "missing_tags" or "missingtags"
	if first["missing_tags"] || first["missingtags"] {
		return ReportTypeTags
	}
	// Secrets: has "match" and "key"
	if first["match"] && first["key"] {
		return ReportTypeSecrets
	}

	return ReportTypeUnknown
}

// NormalizeReport converts any supported report JSON into a slice of NormalizedFindings.
func NormalizeReport(data []byte) ([]NormalizedFinding, error) {
	rt := DetectType(data)
	switch rt {
	case ReportTypeAudit:
		return normalizeAudit(data)
	case ReportTypeIAM:
		return normalizeIAM(data)
	case ReportTypeStorage:
		return normalizeStorage(data)
	case ReportTypeNetwork:
		return normalizeNetwork(data)
	case ReportTypeOrphans:
		return normalizeOrphans(data)
	case ReportTypeCerts:
		return normalizeCerts(data)
	case ReportTypeTags:
		return normalizeTags(data)
	case ReportTypeSecrets:
		return normalizeSecrets(data)
	case ReportTypeCost:
		return nil, fmt.Errorf("cost diff reports cannot be compared as findings")
	case ReportTypeQuotas:
		return normalizeQuotas(data)
	case ReportTypeDrift:
		return normalizeDrift(data)
	default:
		return nil, fmt.Errorf("unknown report type")
	}
}

func normalizeAudit(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		IAM     []cloud.Finding        `json:"iam"`
		Storage []cloud.BucketFinding  `json:"storage"`
		Network []cloud.NetworkFinding `json:"network"`
		Orphans []cloud.OrphanResource `json:"orphans"`
		Certs   []cloud.CertFinding    `json:"certs"`
		Tags    []cloud.TagFinding     `json:"tags"`
		Secrets []cloud.SecretFinding  `json:"secrets"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse audit report: %w", err)
	}

	var all []NormalizedFinding
	for _, f := range report.IAM {
		all = append(all, normalizeIAMFinding(f))
	}
	for _, f := range report.Storage {
		all = append(all, normalizeStorageFinding(f))
	}
	for _, f := range report.Network {
		all = append(all, normalizeNetworkFinding(f))
	}
	for _, f := range report.Orphans {
		all = append(all, normalizeOrphanResource(f))
	}
	for _, f := range report.Certs {
		all = append(all, normalizeCertFinding(f))
	}
	for _, f := range report.Tags {
		all = append(all, normalizeTagFinding(f))
	}
	for _, f := range report.Secrets {
		all = append(all, normalizeSecretFinding(f))
	}
	return all, nil
}

func normalizeIAM(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Findings []cloud.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse IAM report: %w", err)
	}
	var result []NormalizedFinding
	for _, f := range report.Findings {
		result = append(result, normalizeIAMFinding(f))
	}
	return result, nil
}

func normalizeStorage(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Findings []cloud.BucketFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse storage report: %w", err)
	}
	var result []NormalizedFinding
	for _, f := range report.Findings {
		result = append(result, normalizeStorageFinding(f))
	}
	return result, nil
}

func normalizeNetwork(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Findings []cloud.NetworkFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse network report: %w", err)
	}
	var result []NormalizedFinding
	for _, f := range report.Findings {
		result = append(result, normalizeNetworkFinding(f))
	}
	return result, nil
}

func normalizeOrphans(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Resources []cloud.OrphanResource `json:"resources"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse orphans report: %w", err)
	}
	var result []NormalizedFinding
	for _, f := range report.Resources {
		result = append(result, normalizeOrphanResource(f))
	}
	return result, nil
}

func normalizeCerts(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Findings []cloud.CertFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse certs report: %w", err)
	}
	var result []NormalizedFinding
	for _, f := range report.Findings {
		result = append(result, normalizeCertFinding(f))
	}
	return result, nil
}

func normalizeTags(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Findings []cloud.TagFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse tags report: %w", err)
	}
	var result []NormalizedFinding
	for _, f := range report.Findings {
		result = append(result, normalizeTagFinding(f))
	}
	return result, nil
}

func normalizeSecrets(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Findings []cloud.SecretFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse secrets report: %w", err)
	}
	var result []NormalizedFinding
	for _, f := range report.Findings {
		result = append(result, normalizeSecretFinding(f))
	}
	return result, nil
}

func normalizeQuotas(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Quotas []cloud.QuotaUsage `json:"quotas"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse quotas report: %w", err)
	}
	var result []NormalizedFinding
	for _, q := range report.Quotas {
		result = append(result, NormalizedFinding{
			Domain:     "quotas",
			Provider:   q.Provider,
			Type:       q.Service,
			ResourceID: q.QuotaName,
			Detail:     fmt.Sprintf("%.0f/%.0f (%.1f%%)", q.Used, q.Limit, q.Utilization),
			Severity:   string(cloud.QuotaSeverity(q.Utilization)),
		})
	}
	return result, nil
}

func normalizeDrift(data []byte) ([]NormalizedFinding, error) {
	var report struct {
		Results []cloud.DriftResult `json:"results"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse drift report: %w", err)
	}
	var result []NormalizedFinding
	for _, r := range report.Results {
		if r.Status == cloud.DriftInSync {
			continue // an in-sync resource is the absence of drift, not a finding
		}
		result = append(result, normalizeDriftResult(r))
	}
	return result, nil
}

func normalizeIAMFinding(f cloud.Finding) NormalizedFinding {
	resourceID := f.Resource
	if f.Principal != nil {
		resourceID = f.Principal.ID
	}
	return NormalizedFinding{
		Domain:     "iam",
		Provider:   f.Provider,
		Type:       string(f.Type),
		ResourceID: resourceID,
		Detail:     f.Detail,
		Severity:   string(f.Severity),
	}
}

func normalizeStorageFinding(f cloud.BucketFinding) NormalizedFinding {
	return NormalizedFinding{
		Domain:     "storage",
		Provider:   f.Provider,
		Type:       string(f.Type),
		ResourceID: f.Bucket,
		Detail:     f.Detail,
		Severity:   string(f.Severity),
	}
}

func normalizeNetworkFinding(f cloud.NetworkFinding) NormalizedFinding {
	return NormalizedFinding{
		Domain:     "network",
		Provider:   f.Provider,
		Type:       string(f.Type),
		ResourceID: f.Resource,
		Detail:     f.Detail,
		Severity:   string(f.Severity),
	}
}

func normalizeOrphanResource(f cloud.OrphanResource) NormalizedFinding {
	return NormalizedFinding{
		Domain:     "orphans",
		Provider:   f.Provider,
		Type:       string(f.Kind),
		ResourceID: f.ID,
		Detail:     f.Detail,
		Severity:   string(cloud.SeverityMedium),
	}
}

func normalizeCertFinding(f cloud.CertFinding) NormalizedFinding {
	resourceID := f.ARN
	if resourceID == "" {
		resourceID = f.Domain
	}
	return NormalizedFinding{
		Domain:     "certs",
		Provider:   f.Provider,
		Type:       string(f.Status),
		ResourceID: resourceID,
		Detail:     f.Detail,
		Severity:   string(f.Severity),
	}
}

func normalizeTagFinding(f cloud.TagFinding) NormalizedFinding {
	return NormalizedFinding{
		Domain:     "tags",
		Provider:   f.Provider,
		Type:       f.ResourceType,
		ResourceID: f.ResourceID,
		Detail:     f.Detail,
		Severity:   string(f.Severity),
	}
}

func normalizeSecretFinding(f cloud.SecretFinding) NormalizedFinding {
	return NormalizedFinding{
		Domain:     "secrets",
		Provider:   f.Provider,
		Type:       string(f.Type),
		ResourceID: f.Resource,
		Detail:     f.Detail,
		Severity:   string(f.Severity),
	}
}

func normalizeDriftResult(f cloud.DriftResult) NormalizedFinding {
	// The Terraform address is the stable logical identity; fall back to the cloud
	// id when it isn't set.
	resourceID := f.ResourceName
	if resourceID == "" {
		resourceID = f.ResourceID
	}
	detail := f.Detail
	if detail == "" {
		detail = driftFieldsSummary(f.Fields)
	}
	return NormalizedFinding{
		Domain:     "drift",
		Provider:   f.Provider,
		Type:       string(f.Status),
		ResourceID: resourceID,
		Detail:     detail,
		Severity:   string(driftSeverity(f.Status)),
	}
}

// driftSeverity ranks a drift status: a resource that vanished from the cloud is
// more urgent than one whose config drifted, and an un-checkable resource is
// informational.
func driftSeverity(s cloud.DriftStatus) cloud.Severity {
	switch s {
	case cloud.DriftDeleted:
		return cloud.SeverityHigh
	case cloud.DriftModified:
		return cloud.SeverityMedium
	case cloud.DriftError:
		return cloud.SeverityLow
	default:
		return cloud.SeverityMedium
	}
}

// driftFieldsSummary lists the drifted field names, so two reports whose drift on
// the same resource differs don't collapse to the same MatchKey.
func driftFieldsSummary(fields []cloud.DriftField) string {
	if len(fields) == 0 {
		return ""
	}
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, f.Field)
	}
	return "drifted: " + strings.Join(names, ", ")
}
