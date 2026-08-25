package compliance

import "github.com/nanohype/cloudgov/internal/cloud"

// ControlStatus describes the evaluation result of a control.
type ControlStatus string

const (
	StatusPass         ControlStatus = "PASS"
	StatusFail         ControlStatus = "FAIL"
	StatusNotEvaluated ControlStatus = "NOT_EVALUATED"
)

// Control defines a single benchmark control.
type Control struct {
	ID          string
	Title       string
	Description string
	Section     string
	Severity    cloud.Severity
}

// ControlResult is the evaluated outcome of a single control.
type ControlResult struct {
	Control  Control
	Status   ControlStatus
	Findings []string // references to specific findings that triggered this control
	Detail   string
}

// ComplianceSummary aggregates pass/fail/not-evaluated counts.
type ComplianceSummary struct {
	Total        int `json:"total"`
	Passed       int `json:"passed"`
	Failed       int `json:"failed"`
	NotEvaluated int `json:"not_evaluated"`
}

// ComplianceReport is the full output of a compliance evaluation.
type ComplianceReport struct {
	Benchmark string            `json:"benchmark"`
	Summary   ComplianceSummary `json:"summary"`
	Results   []ControlResult   `json:"results"`
	// Incomplete names what the scans behind this evaluation could not read.
	//
	// A benchmark verdict is only as complete as its inputs. A control evaluated
	// against a scan that was denied half an account reads exactly like one
	// evaluated against a whole account, and it is the surface where that
	// difference matters most: the output is the artifact someone points at to
	// say a control passed. Always present, empty when every input was whole.
	Incomplete []string `json:"incomplete"`
}

// InputFindings holds all finding types loaded from cloudgov scan JSON reports.
type InputFindings struct {
	IAM     []cloud.Finding
	Storage []cloud.BucketFinding
	Network []cloud.NetworkFinding
	Certs   []cloud.CertFinding
	Tags    []cloud.TagFinding
}
