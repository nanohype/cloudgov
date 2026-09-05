package compliance

import (
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// A control that cannot fail is not a control.
//
// Both generic evaluators once returned PASS for any non-empty report without
// reading the control or any finding, so eight CIS controls — root access keys,
// root MFA, EBS encryption among them — reported PASS on every account cloudgov
// has ever scanned. Line coverage said nothing: both functions run on every
// Evaluate call, so they were fully covered while none of their behaviour was
// asserted. Coverage of a function with no failing branch is not evidence that
// the function decides anything.
//
// So every published control must be one of two things, and say which:
//
//   - it can FAIL, shown by an input that makes it fail — not by reading the
//     evaluator, which is how the shape above survived review
//   - it cannot be evaluated from what cloudgov collects, named here with what
//     would have to be collected
//
// A control in neither fails this test. That is the whole of the population
// question: the controls come from the benchmarks themselves, so a control added
// to either one arrives here without an edit and has to be answered.

// cisFailingWitness is an input that must make its CIS control report FAIL.
//
// Minimal on purpose. A witness carrying findings in every domain would fail
// several controls at once, and a control that failed for a neighbour's finding
// would look answered.
var cisFailingWitness = map[string]InputFindings{
	"1.16":  {IAM: []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin", Detail: "AdministratorAccess attached"}}},
	"1.10":  {IAM: []cloud.Finding{{Type: cloud.FindingStalePrincipal, Resource: "user/ci", Detail: "no activity in 400 days"}}},
	"1.12":  {IAM: []cloud.Finding{{Type: cloud.FindingStalePrincipal, Resource: "user/ci", Detail: "access key unused for 400 days"}}},
	"1.15":  {IAM: []cloud.Finding{{Type: cloud.FindingWildcardResource, Resource: "role/deploy", Detail: "Resource: *"}}},
	"2.1.4": {Storage: []cloud.BucketFinding{{Type: cloud.BucketUnencrypted, Bucket: "artifacts", Detail: "no default encryption"}}},
	"2.1.5": {Storage: []cloud.BucketFinding{{Type: cloud.BucketPublicAccess, Bucket: "artifacts", Detail: "block public access is off"}}},
	"3.7":   {Storage: []cloud.BucketFinding{{Type: cloud.BucketNoLogging, Bucket: "artifacts", Detail: "no access logging"}}},
	"4.1":   {Tags: []cloud.TagFinding{{ResourceID: "i-0abc", MissingTags: []string{"Environment"}}}},
	"5.1":   {Network: []cloud.NetworkFinding{{Type: cloud.NetworkAdminPortOpen, Resource: "sg-1", Detail: "22 open to 0.0.0.0/0"}}},
	"5.2":   {Network: []cloud.NetworkFinding{{Type: cloud.NetworkAdminPortOpen, Resource: "sg-1", Detail: "22 open to 0.0.0.0/0"}}},
	"5.3":   {Network: []cloud.NetworkFinding{{Type: cloud.NetworkAdminPortOpen, Resource: "sg-2", Detail: "3389 open to 0.0.0.0/0"}}},
}

// benchmarkWitnesses returns, per benchmark, the failing witness for each
// control that can fail and the reason for each that cannot.
//
// Neither half is written twice. The reasons are the production tables the
// evaluator dispatches on, and SOC 2's witnesses are the ones soc2_test.go
// already drives: two hand-kept copies of "the input that fails CC6.1" agreeing
// with each other says nothing about either agreeing with the evaluator, and a
// second copy of "what 1.4 needs" would let the report and this test disagree
// about the same control.
func benchmarkWitnesses(id string) (map[string]InputFindings, map[string]string) {
	switch id {
	case "cis-aws-v3":
		return cisFailingWitness, cisUncollected
	case "soc2":
		failing := map[string]InputFindings{}
		for control, tc := range soc2Evaluatable {
			failing[control] = tc.failing
		}
		return failing, soc2Uncollected
	}
	return nil, nil
}

func TestEveryPublishedControlCanFailOrNamesWhatIsMissing(t *testing.T) {
	// Findings in every domain, for the controls that must decline. A control
	// declining only on an empty input would otherwise satisfy this without
	// deciding anything, which is the shape being ruled out.
	loaded := InputFindings{
		IAM:     []cloud.Finding{{Type: cloud.FindingAdminAccess, Resource: "role/admin", Detail: "full admin"}},
		Storage: []cloud.BucketFinding{{Type: cloud.BucketPublicAccess, Bucket: "docs"}},
		Network: []cloud.NetworkFinding{{Type: cloud.NetworkAdminPortOpen, Resource: "sg-1"}},
		Tags:    []cloud.TagFinding{{ResourceID: "raw", MissingTags: []string{"Team"}}},
		Certs:   []cloud.CertFinding{{Status: cloud.CertExpired, Domain: "api.example.test"}},
	}

	published := AvailableBenchmarks()
	if len(published) == 0 {
		t.Fatal("no benchmark is published; this test would pass over nothing")
	}

	for _, id := range published {
		benchmark := GetBenchmark(id)
		if benchmark == nil {
			t.Fatalf("benchmark %s is published and does not resolve", id)
		}
		// Per benchmark, not once over the sum. A benchmark that stopped
		// publishing controls contributes nothing and is not distinguishable from
		// one whose controls all passed, unless each is required to carry some.
		if len(benchmark.Controls) == 0 {
			t.Errorf("benchmark %s publishes no control", id)
			continue
		}

		failing, cannot := benchmarkWitnesses(id)
		if len(failing) == 0 && len(cannot) == 0 {
			t.Errorf("benchmark %s is published and this test has no witnesses for it, so its "+
				"controls are unexamined here", id)
			continue
		}

		declared := map[string]bool{}
		for _, ctrl := range benchmark.Controls {
			declared[ctrl.ID] = true
			witness, canFail := failing[ctrl.ID]
			reason, declined := cannot[ctrl.ID]

			switch {
			case canFail && declined:
				t.Errorf("%s %s has both a failing witness and a reason it cannot be evaluated; "+
					"one of the two is wrong", id, ctrl.ID)

			case !canFail && !declined:
				t.Errorf("%s %s is published and nothing shows it can fail. Give it an input that "+
					"makes it FAIL, or name what would have to be collected for it — a control "+
					"that cannot fail reports PASS on every account and is not a control",
					id, ctrl.ID)

			case canFail:
				got := resultFor(t, benchmark, witness, ctrl.ID)
				if got.Status != StatusFail {
					t.Errorf("%s %s = %s on the input written to fail it, want FAIL: %s",
						id, ctrl.ID, got.Status, got.Detail)
					continue
				}
				if len(got.Findings) == 0 {
					t.Errorf("%s %s failed and cites no finding, so an auditor cannot see what "+
						"failed it", id, ctrl.ID)
				}

			case declined:
				got := resultFor(t, benchmark, loaded, ctrl.ID)
				if got.Status != StatusNotEvaluated {
					t.Errorf("%s %s = %s with findings loaded in every domain, want NOT_EVALUATED "+
						"— it is listed as unanswerable because %s", id, ctrl.ID, got.Status, reason)
					continue
				}
				// The detail carries the probe, not just the refusal. "Not
				// evaluated" tells an auditor the tool declined; naming the
				// missing collector tells them what would close it.
				if !strings.Contains(got.Detail, reason) {
					t.Errorf("%s %s declines with %q, which does not name what is missing (%q), "+
						"so a reader learns that the tool refused and not what would answer it",
						id, ctrl.ID, got.Detail, reason)
				}
				// The Status and the Description travel in the same JSON and an
				// auditor reads both. A control the tool never evaluated whose own
				// description does not say so reads, to anyone scanning
				// descriptions, exactly like one it checked.
				if !strings.Contains(ctrl.Description, "reported as not evaluated") {
					t.Errorf("%s %s is never evaluated and its description does not say so: %q",
						id, ctrl.ID, ctrl.Description)
				}
			}
		}

		// A witness for a control the benchmark does not publish exercises
		// nothing and hides that the map has drifted from the benchmark.
		for control := range failing {
			if !declared[control] {
				t.Errorf("%s has a failing witness for %s, which the benchmark does not publish", id, control)
			}
		}
		for control := range cannot {
			if !declared[control] {
				t.Errorf("%s names %s as unanswerable, and the benchmark does not publish it", id, control)
			}
		}
	}
}

// resultFor evaluates a benchmark against one input and returns the result for
// one control.
//
// It goes through Evaluate rather than calling an evaluator, so what is asserted
// is the verdict that reaches a report — dispatch included. Routing a control to
// the wrong evaluator is a defect this catches and a direct call cannot.
func resultFor(t *testing.T, benchmark *Benchmark, input InputFindings, controlID string) ControlResult {
	t.Helper()
	for _, r := range Evaluate(benchmark, input).Results {
		if r.Control.ID == controlID {
			return r
		}
	}
	t.Fatalf("control %s is not in the %s report", controlID, benchmark.ID)
	return ControlResult{}
}
