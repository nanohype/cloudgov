package compliance

import (
	"github.com/nanohype/cloudgov/internal/cloud"
)

// Evaluate runs all controls in a benchmark against the provided findings.
func Evaluate(benchmark *Benchmark, input InputFindings) ComplianceReport {
	results := make([]ControlResult, 0, len(benchmark.Controls))
	for _, ctrl := range benchmark.Controls {
		results = append(results, evaluateControl(benchmark.ID, ctrl, input))
	}

	var summary ComplianceSummary
	summary.Total = len(results)
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
		case StatusNotEvaluated:
			summary.NotEvaluated++
		}
	}

	return ComplianceReport{
		Benchmark: benchmark.Name,
		Summary:   summary,
		Results:   results,
	}
}

func evaluateControl(benchmarkID string, ctrl Control, input InputFindings) ControlResult {
	switch benchmarkID {
	case "cis-aws-v3":
		return evaluateCISAWS(ctrl, input)
	case "soc2":
		return evaluateSOC2(ctrl, input)
	default:
		return evalNotEvaluated(ctrl, "no evaluator for benchmark "+benchmarkID)
	}
}

// --- CIS AWS v3 ---

func evaluateCISAWS(ctrl Control, input InputFindings) ControlResult {
	if probe, uncollected := cisUncollected[ctrl.ID]; uncollected {
		return evalNotEvaluated(ctrl, uncollectedDetail(probe))
	}
	switch ctrl.ID {
	// IAM controls
	case "1.16":
		return evalAdminAccess(ctrl, input.IAM)
	case "1.10", "1.12":
		return evalStalePrincipal(ctrl, input.IAM)
	case "1.15":
		return evalBroadScope(ctrl, input.IAM)
	// Storage controls
	case "2.1.4":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketUnencrypted)
	case "2.1.5":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketPublicAccess)
	// Logging controls
	case "3.7":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketNoLogging)
	// Monitoring
	case "4.1":
		return evalTags(ctrl, input.Tags)

	// Networking
	case "5.1":
		return evalNetworkFinding(ctrl, input.Network, cloud.NetworkAdminPortOpen)
	case "5.2", "5.3":
		return evalNetworkAdminPorts(ctrl, input.Network)
	default:
		return evalNotEvaluated(ctrl, "no evaluator for this control")
	}
}

// --- SOC 2 Type II ---

func evaluateSOC2(ctrl Control, input InputFindings) ControlResult {
	if probe, uncollected := soc2Uncollected[ctrl.ID]; uncollected {
		return evalNotEvaluated(ctrl, uncollectedDetail(probe))
	}
	switch ctrl.ID {
	// CC6 — Logical and Physical Access Controls
	case "CC6.1":
		return evalAdminAccess(ctrl, input.IAM)
	case "CC6.2":
		return evalStalePrincipal(ctrl, input.IAM)
	case "CC6.3":
		return evalBroadScope(ctrl, input.IAM)
	case "CC6.6":
		return evalNetworkFinding(ctrl, input.Network, cloud.NetworkAdminPortOpen)
	case "CC6.7":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketUnencrypted)

	// CC7 — System Operations
	case "CC7.2":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketNoLogging)

	// A1 — Availability
	case "A1.2":
		return evalCerts(ctrl, input.Certs)

	// C1 — Confidentiality
	case "C1.1":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketPublicAccess)
	case "C1.2":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketUnencrypted)

	// P6 — Privacy
	case "P6.1":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketPublicACL)

	// Not evaluatable — require organizational / process data
	default:
		return evalNotEvaluated(ctrl, "no evaluator for this control")
	}
}

// --- Shared evaluator helpers ---

func evalAdminAccess(ctrl Control, findings []cloud.Finding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no IAM findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == cloud.FindingAdminAccess {
			ref := f.Detail
			if f.Principal != nil {
				ref = f.Principal.Name + ": " + f.Detail
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "admin access policies found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no admin access policies detected"}
}

func evalStalePrincipal(ctrl Control, findings []cloud.Finding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no IAM findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == cloud.FindingStalePrincipal || f.Type == cloud.FindingUnusedPermission {
			ref := f.Detail
			if f.Principal != nil {
				ref = f.Principal.Name + ": " + f.Detail
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "stale or unused credentials found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no stale credentials detected"}
}

func evalBroadScope(ctrl Control, findings []cloud.Finding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no IAM findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == cloud.FindingBroadScope || f.Type == cloud.FindingWildcardResource {
			ref := f.Detail
			if f.Principal != nil {
				ref = f.Principal.Name + ": " + f.Detail
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "broad scope or wildcard resource policies found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no broad scope policies detected"}
}

func evalStorageFinding(ctrl Control, findings []cloud.BucketFinding, findingType cloud.BucketFindingType) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no storage findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == findingType {
			refs = append(refs, f.Bucket+": "+f.Detail)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: string(findingType) + " issues found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no " + string(findingType) + " issues detected"}
}

func evalNetworkFinding(ctrl Control, findings []cloud.NetworkFinding, findingType cloud.NetworkFindingType) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no network findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == findingType {
			refs = append(refs, f.Resource+": "+f.Detail)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: string(findingType) + " issues found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no " + string(findingType) + " issues detected"}
}

func evalNetworkAdminPorts(ctrl Control, findings []cloud.NetworkFinding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no network findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == cloud.NetworkAdminPortOpen {
			refs = append(refs, f.Resource+": "+f.Detail)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "admin ports open to internet"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no admin ports open to internet"}
}

func evalCerts(ctrl Control, findings []cloud.CertFinding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no certificate findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Status == cloud.CertExpired || f.Status == cloud.CertCritical {
			refs = append(refs, f.Domain+": "+f.Detail)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "expired or critically expiring certificates found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no critical certificate expiry detected"}
}

// evalTags has no PASS arm, unlike the other domain evaluators. A tags report
// lists only the resources that are missing a required tag, so a finding is a
// failure by construction and an empty report is the clean case — which is
// indistinguishable here from a tags scan nobody ran, hence NOT_EVALUATED.
func evalTags(ctrl Control, findings []cloud.TagFinding) ControlResult {
	if len(findings) == 0 {
		return evalNotEvaluated(ctrl, "no tags findings provided")
	}
	refs := make([]string, 0, len(findings))
	for _, f := range findings {
		refs = append(refs, f.ResourceID+": missing "+joinTags(f.MissingTags))
	}
	return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "resources missing required tags"}
}

func evalNotEvaluated(ctrl Control, reason string) ControlResult {
	return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: reason}
}

func joinTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	s := tags[0]
	for _, t := range tags[1:] {
		s += ", " + t
	}
	return s
}
