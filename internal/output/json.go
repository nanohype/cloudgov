package output

import (
	"encoding/json"
	"io"

	"github.com/stxkxs/matlock/internal/audit"
	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/compliance"
)

type iamReport struct {
	Findings        []cloud.Finding               `json:"findings"`
	Total           int                           `json:"total"`
	Principals      int                           `json:"principals_scanned"`
	UsedPermissions map[string][]cloud.Permission `json:"used_permissions,omitempty"`
}

type storageReport struct {
	Findings []cloud.BucketFinding `json:"findings"`
	Total    int                   `json:"total"`
}

type orphansReport struct {
	Resources           []cloud.OrphanResource `json:"resources"`
	Total               int                    `json:"total"`
	EstimatedMonthlyUSD float64                `json:"estimated_monthly_usd"`
}

type costReport struct {
	Diffs []cloud.CostDiff `json:"diffs"`
}

// WriteIAM marshals IAM findings as JSON to w.
func WriteIAM(w io.Writer, findings []cloud.Finding, principalsScanned int, usedPerms map[string][]cloud.Permission) error {
	return writeJSON(w, iamReport{
		Findings:        findings,
		Total:           len(findings),
		Principals:      principalsScanned,
		UsedPermissions: usedPerms,
	})
}

// WriteStorage marshals storage findings as JSON to w.
func WriteStorage(w io.Writer, findings []cloud.BucketFinding) error {
	return writeJSON(w, storageReport{
		Findings: findings,
		Total:    len(findings),
	})
}

// WriteOrphans marshals orphan resources as JSON to w.
func WriteOrphans(w io.Writer, orphans []cloud.OrphanResource) error {
	var total float64
	for _, o := range orphans {
		total += o.MonthlyCost
	}
	return writeJSON(w, orphansReport{
		Resources:           orphans,
		Total:               len(orphans),
		EstimatedMonthlyUSD: total,
	})
}

// WriteCost marshals cost diffs as JSON to w.
func WriteCost(w io.Writer, diffs []cloud.CostDiff) error {
	return writeJSON(w, costReport{Diffs: diffs})
}

type networkReport struct {
	Findings []cloud.NetworkFinding `json:"findings"`
	Total    int                    `json:"total"`
}

type certsReport struct {
	Findings []cloud.CertFinding `json:"findings"`
	Total    int                 `json:"total"`
}

type tagsReport struct {
	Findings []cloud.TagFinding `json:"findings"`
	Total    int                `json:"total"`
}

// WriteNetwork marshals network findings as JSON to w.
func WriteNetwork(w io.Writer, findings []cloud.NetworkFinding) error {
	return writeJSON(w, networkReport{Findings: findings, Total: len(findings)})
}

// WriteCerts marshals certificate findings as JSON to w.
func WriteCerts(w io.Writer, findings []cloud.CertFinding) error {
	return writeJSON(w, certsReport{Findings: findings, Total: len(findings)})
}

// WriteTags marshals tag findings as JSON to w.
func WriteTags(w io.Writer, findings []cloud.TagFinding) error {
	return writeJSON(w, tagsReport{Findings: findings, Total: len(findings)})
}

type secretsReport struct {
	Findings []cloud.SecretFinding `json:"findings"`
	Total    int                   `json:"total"`
}

// WriteSecrets marshals secret findings as JSON to w.
func WriteSecrets(w io.Writer, findings []cloud.SecretFinding) error {
	return writeJSON(w, secretsReport{Findings: findings, Total: len(findings)})
}

type driftReport struct {
	Results []cloud.DriftResult `json:"results"`
	Total   int                 `json:"total"`
}

// WriteDrift marshals drift results as JSON to w.
func WriteDrift(w io.Writer, results []cloud.DriftResult) error {
	return writeJSON(w, driftReport{Results: results, Total: len(results)})
}

// WriteCompliance marshals a compliance report as JSON to w.
func WriteCompliance(w io.Writer, report compliance.ComplianceReport) error {
	return writeJSON(w, report)
}

// WriteAudit marshals a full audit report as JSON to w.
func WriteAudit(w io.Writer, report *audit.Report) error {
	return writeJSON(w, report)
}

type k8sReport struct {
	Findings []cloud.K8sFinding `json:"findings"`
	Total    int                `json:"total"`
}

// WriteK8sFindings marshals Kubernetes findings as JSON to w.
func WriteK8sFindings(w io.Writer, findings []cloud.K8sFinding) error {
	return writeJSON(w, k8sReport{Findings: findings, Total: len(findings)})
}

type lambdaPolicyReport struct {
	Findings []cloud.LambdaPolicyFinding `json:"findings"`
	Total    int                         `json:"total"`
}

// WriteLambdaPolicy marshals Lambda resource-policy findings as JSON to w.
func WriteLambdaPolicy(w io.Writer, findings []cloud.LambdaPolicyFinding) error {
	return writeJSON(w, lambdaPolicyReport{Findings: findings, Total: len(findings)})
}

type inventoryReport struct {
	Resources []cloud.InventoryResource `json:"resources"`
	Total     int                       `json:"total"`
}

// WriteInventory marshals inventory resources as JSON to w.
func WriteInventory(w io.Writer, resources []cloud.InventoryResource) error {
	return writeJSON(w, inventoryReport{
		Resources: resources,
		Total:     len(resources),
	})
}

type quotaReport struct {
	Quotas   []cloud.QuotaUsage `json:"quotas"`
	Total    int                `json:"total"`
	Critical int                `json:"critical"`
	High     int                `json:"high"`
	Medium   int                `json:"medium"`
}

// WriteQuotas marshals quota usage data as JSON to w.
func WriteQuotas(w io.Writer, quotas []cloud.QuotaUsage) error {
	var crit, high, med int
	for _, q := range quotas {
		switch cloud.QuotaSeverity(q.Utilization) {
		case cloud.SeverityCritical:
			crit++
		case cloud.SeverityHigh:
			high++
		case cloud.SeverityMedium:
			med++
		}
	}
	return writeJSON(w, quotaReport{
		Quotas:   quotas,
		Total:    len(quotas),
		Critical: crit,
		High:     high,
		Medium:   med,
	})
}

type compareReport struct {
	New       []CompareFindingJSONType `json:"new"`
	Resolved  []CompareFindingJSONType `json:"resolved"`
	Unchanged []CompareFindingJSONType `json:"unchanged"`
	Summary   compareSummary           `json:"summary"`
}

// CompareFindingJSONType is a finding for JSON comparison output.
type CompareFindingJSONType struct {
	Domain     string `json:"domain"`
	Provider   string `json:"provider"`
	Type       string `json:"type"`
	ResourceID string `json:"resource_id"`
	Detail     string `json:"detail"`
	Severity   string `json:"severity"`
}

type compareSummary struct {
	New       int `json:"new"`
	Resolved  int `json:"resolved"`
	Unchanged int `json:"unchanged"`
}

// WriteCompare marshals comparison results as JSON to w.
func WriteCompare(w io.Writer, newF, resolved, unchanged []CompareFindingJSONType) error {
	return writeJSON(w, compareReport{
		New:       newF,
		Resolved:  resolved,
		Unchanged: unchanged,
		Summary: compareSummary{
			New:       len(newF),
			Resolved:  len(resolved),
			Unchanged: len(unchanged),
		},
	})
}

// CompareFindingJSON creates a CompareFindingJSONType.
func CompareFindingJSON(domain, provider, typ, resourceID, detail, severity string) CompareFindingJSONType {
	return CompareFindingJSONType{
		Domain: domain, Provider: provider, Type: typ,
		ResourceID: resourceID, Detail: detail, Severity: severity,
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
