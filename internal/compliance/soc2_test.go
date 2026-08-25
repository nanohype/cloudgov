package compliance

import (
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// This file covers the SOC 2 Type II evaluator. A control here decides whether an
// auditor is told a Trust Services criterion passed, so a branch nobody exercised
// is a verdict nobody has proven the tool can reach.

// evaluatable names every SOC 2 control that maps to a real evaluator, with the
// finding set that must fail it and the set that must pass it. `notEvaluatable`
// names the rest. Together they must cover the benchmark exactly — see
// TestSOC2CoversEveryPublishedControl, which is what stops a control added to
// soc2.go from arriving untested.
var soc2Evaluatable = map[string]struct {
	failing InputFindings
	passing InputFindings
}{
	"CC6.1": {
		failing: InputFindings{IAM: []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin", Detail: "full admin"}}},
		passing: InputFindings{IAM: []cloud.Finding{{Type: cloud.FindingUnusedPermission, Resource: "role/app"}}},
	},
	"CC6.2": {
		failing: InputFindings{IAM: []cloud.Finding{{Type: cloud.FindingStalePrincipal, Resource: "user/dormant"}}},
		passing: InputFindings{IAM: []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin"}}},
	},
	"CC6.3": {
		failing: InputFindings{IAM: []cloud.Finding{{Type: cloud.FindingWildcardResource, Resource: "role/wide"}}},
		passing: InputFindings{IAM: []cloud.Finding{{Type: cloud.FindingStalePrincipal, Resource: "user/dormant"}}},
	},
	"CC6.6": {
		failing: InputFindings{Network: []cloud.NetworkFinding{{Type: cloud.NetworkAdminPortOpen, Resource: "sg-1", Detail: "22/tcp open to 0.0.0.0/0"}}},
		passing: InputFindings{Network: []cloud.NetworkFinding{{Type: cloud.NetworkOpenIngress, Resource: "sg-2"}}},
	},
	"CC6.7": {
		failing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketUnencrypted, Bucket: "raw"}}},
		passing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketNoVersioning, Bucket: "raw"}}},
	},
	"CC7.2": {
		failing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketNoLogging, Bucket: "audit"}}},
		passing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketUnencrypted, Bucket: "audit"}}},
	},
	"A1.2": {
		failing: InputFindings{Certs: []cloud.CertFinding{{Status: cloud.CertExpired, Domain: "api.example.test", Detail: "expired"}}},
		passing: InputFindings{Certs: []cloud.CertFinding{{Status: cloud.CertLow, Domain: "api.example.test"}}},
	},
	"C1.1": {
		failing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketPublicAccess, Bucket: "docs"}}},
		passing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketNoLogging, Bucket: "docs"}}},
	},
	"C1.2": {
		failing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketUnencrypted, Bucket: "docs"}}},
		passing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketNoLogging, Bucket: "docs"}}},
	},
	"P6.1": {
		failing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketPublicACL, Bucket: "pii"}}},
		passing: InputFindings{Storage: []cloud.BucketFinding{{Type: cloud.BucketNoLogging, Bucket: "pii"}}},
	},
}

// soc2NotEvaluatable are the criteria that need organizational evidence a cloud
// API cannot supply. They must report NOT_EVALUATED and never PASS: a criterion
// nobody checked reported as passed is the failure this benchmark exists to make
// visible.
// CC7.1 joins them: it maps to evalIAMGeneric, which serves criteria an IAM scan
// is evidence toward but does not decide, and so holds no verdict either.
var soc2NotEvaluatable = []string{"CC1.1", "CC2.1", "CC3.1", "CC4.1", "CC5.1", "CC7.1", "CC8.1", "CC9.1"}

func soc2Control(t *testing.T, id string) Control {
	t.Helper()
	for _, c := range soc2TypeIIBenchmark().Controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s is not in the SOC 2 benchmark", id)
	return Control{}
}

func TestEvaluateSOC2_EvaluatableControls(t *testing.T) {
	for id, tc := range soc2Evaluatable {
		t.Run(id+"/fails on its own finding", func(t *testing.T) {
			got := evaluateSOC2(soc2Control(t, id), tc.failing)
			if got.Status != StatusFail {
				t.Fatalf("status = %s, want FAIL — the finding this control watches for did not fail it: %+v", got.Status, got)
			}
			if len(got.Findings) == 0 {
				t.Error("a FAIL cites no finding, so an auditor cannot see what failed it")
			}
		})
		t.Run(id+"/passes on unrelated findings", func(t *testing.T) {
			got := evaluateSOC2(soc2Control(t, id), tc.passing)
			if got.Status == StatusFail {
				t.Fatalf("status = FAIL on findings this control does not watch: %+v", got)
			}
		})
	}
}

func TestEvaluateSOC2_NotEvaluatableControls(t *testing.T) {
	// Findings are present so a control that declines only on an empty input
	// cannot pass this by accident: the point is that it declines regardless.
	loaded := InputFindings{
		IAM:     []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin", Detail: "full admin"}},
		Storage: []cloud.BucketFinding{{Type: cloud.BucketPublicAccess, Bucket: "docs"}},
	}
	for _, id := range soc2NotEvaluatable {
		t.Run(id, func(t *testing.T) {
			got := evaluateSOC2(soc2Control(t, id), loaded)
			if got.Status != StatusNotEvaluated {
				t.Fatalf("status = %s, want NOT_EVALUATED — a criterion needing organizational evidence must not report a verdict", got.Status)
			}
			if got.Detail == "" {
				t.Error("NOT_EVALUATED carries no reason, so a reader cannot tell why the tool declined")
			}
		})
	}
}

// A control id the evaluator does not recognise must decline rather than fall
// through to a verdict.
func TestEvaluateSOC2_UnknownControlDeclines(t *testing.T) {
	got := evaluateSOC2(Control{ID: "ZZ9.9", Title: "invented"}, InputFindings{
		IAM: []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin"}},
	})
	if got.Status != StatusNotEvaluated {
		t.Fatalf("status = %s, want NOT_EVALUATED for an unrecognised control", got.Status)
	}
}

// The population check. Every control the benchmark publishes is either mapped to
// an evaluator here or listed as needing organizational evidence — so a control
// added to soc2.go fails this test rather than shipping with no coverage and no
// tell.
func TestSOC2CoversEveryPublishedControl(t *testing.T) {
	covered := make(map[string]bool, len(soc2Evaluatable)+len(soc2NotEvaluatable))
	for id := range soc2Evaluatable {
		covered[id] = true
	}
	for _, id := range soc2NotEvaluatable {
		covered[id] = true
	}

	published := make(map[string]bool)
	for _, c := range soc2TypeIIBenchmark().Controls {
		published[c.ID] = true
		if !covered[c.ID] {
			t.Errorf("control %s is published in the benchmark but no case in this file exercises it", c.ID)
		}
	}
	for id := range covered {
		if !published[id] {
			t.Errorf("this file exercises control %s, which the benchmark no longer publishes", id)
		}
	}
}

// evaluateControl dispatches on the benchmark id, so a report can only carry SOC 2
// verdicts if this arm is wired. An unknown benchmark declines rather than
// silently evaluating against the wrong criteria.
func TestEvaluateControlDispatchesByBenchmark(t *testing.T) {
	ctrl := soc2Control(t, "CC6.1")
	input := InputFindings{IAM: []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin"}}}

	if got := evaluateControl("soc2", ctrl, input); got.Status != StatusFail {
		t.Errorf("soc2 arm: status = %s, want FAIL", got.Status)
	}
	got := evaluateControl("iso-27001", ctrl, input)
	if got.Status != StatusNotEvaluated {
		t.Errorf("unknown benchmark: status = %s, want NOT_EVALUATED", got.Status)
	}
	if got.Detail == "" {
		t.Error("unknown benchmark declines with no reason")
	}
}

// The whole SOC 2 report end to end: every published control is evaluated exactly
// once and the summary counts add up to the control count. A summary that does not
// account for every control is a report an auditor cannot reconcile.
func TestEvaluateSOC2Report(t *testing.T) {
	bench := GetBenchmark("soc2")
	if bench == nil {
		t.Fatal(`GetBenchmark("soc2") returned nil; the benchmark is not registered`)
	}
	report := Evaluate(bench, InputFindings{
		IAM:     []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin", Detail: "full admin"}},
		Storage: []cloud.BucketFinding{{Type: cloud.BucketPublicAccess, Bucket: "docs"}},
	})

	if report.Summary.Total != len(bench.Controls) {
		t.Errorf("summary total = %d, want %d controls", report.Summary.Total, len(bench.Controls))
	}
	if len(report.Results) != len(bench.Controls) {
		t.Errorf("results = %d, want one per control (%d)", len(report.Results), len(bench.Controls))
	}
	if sum := report.Summary.Passed + report.Summary.Failed + report.Summary.NotEvaluated; sum != report.Summary.Total {
		t.Errorf("pass+fail+not-evaluated = %d, does not account for all %d controls", sum, report.Summary.Total)
	}
	if report.Summary.Failed == 0 {
		t.Error("a report built from an admin-access and a public-bucket finding failed no control")
	}
}
