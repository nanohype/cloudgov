package compliance

import (
	"fmt"

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
	switch ctrl.ID {
	// IAM controls
	case "1.16":
		return evalAdminAccess(ctrl, input.IAM)
	case "1.10", "1.12":
		return evalStalePrincipal(ctrl, input.IAM)
	case "1.15":
		return evalBroadScope(ctrl, input.IAM)
	case "1.4", "1.5", "1.17", "1.19", "1.22":
		return evalIAMGeneric(ctrl, input.IAM)

	// Storage controls
	case "2.1.4":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketUnencrypted)
	case "2.1.5":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketPublicAccess)
	case "2.1.1", "2.1.2", "2.2.1":
		return evalStorageGeneric(ctrl, input.Storage)

	// Logging controls
	case "3.7":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketNoLogging)
	case "3.1", "3.4":
		return evalNotEvaluated(ctrl, "CloudTrail configuration not included in scan data")

	// Monitoring
	case "4.1":
		return evalTags(ctrl, input.Tags)

	// Networking
	case "5.1":
		return evalNetworkFinding(ctrl, input.Network, cloud.NetworkAdminPortOpen)
	case "5.2", "5.3":
		return evalNetworkAdminPorts(ctrl, input.Network)
	case "5.4":
		return evalNetworkFinding(ctrl, input.Network, cloud.NetworkOpenIngress)

	default:
		return evalNotEvaluated(ctrl, "no evaluator for this control")
	}
}

// --- SOC 2 Type II ---

func evaluateSOC2(ctrl Control, input InputFindings) ControlResult {
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
	case "CC7.1":
		return evalIAMGeneric(ctrl, input.IAM)
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
	case "CC1.1", "CC2.1", "CC3.1", "CC4.1", "CC5.1", "CC8.1", "CC9.1":
		return evalNotEvaluated(ctrl, "requires organizational policy review, not cloud API data")

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

// evalIAMGeneric serves the controls whose criterion an IAM scan is evidence
// toward but does not decide: password policy, credential rotation cadence, MFA
// enrolment, change-management review. cloudgov reads none of those, so it holds
// no evidence either way and reports NOT_EVALUATED with the IAM finding count as
// context.
//
// It must never report PASS. A control this evaluator serves is one nothing
// examined, and PASS is the answer an auditor reads as "examined and clean" —
// the same conflation the incomplete contract exists to prevent elsewhere in
// this tool, arriving here as a compliance verdict.
func evalIAMGeneric(ctrl Control, findings []cloud.Finding) ControlResult {
	if len(findings) == 0 {
		return evalNotEvaluated(ctrl, "no IAM findings provided")
	}
	return evalNotEvaluated(ctrl, fmt.Sprintf(
		"cloudgov has no evaluator for this control; the %d IAM finding(s) loaded are context, not a verdict", len(findings)))
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

// evalStorageGeneric serves the storage controls a storage audit is evidence
// toward but does not decide: bucket-policy HTTPS enforcement, MFA Delete, and
// EBS volume encryption. cloudgov reads none of those three states.
//
// It must never report PASS, for the same reason evalIAMGeneric must not. A
// control this evaluator serves is one nothing examined, and PASS is what an
// auditor reads as "examined and clean" — a verdict the tool cannot compute, in
// the artifact someone points at to say a control passed. Returning PASS because
// a storage scan produced findings about something else is the conflation the
// incomplete contract prevents everywhere else in this tool, arriving as a
// compliance verdict.
//
// It declines in both cases, naming the finding count as context rather than as
// a verdict.
func evalStorageGeneric(ctrl Control, findings []cloud.BucketFinding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no storage findings provided"}
	}
	return evalNotEvaluated(ctrl, fmt.Sprintf(
		"cloudgov has no evaluator for this control; the %d storage finding(s) loaded are context, not a verdict", len(findings)))
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
