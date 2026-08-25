package audit

import (
	"reflect"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// oneOfEach builds a report carrying exactly one finding in every domain the
// Report struct declares.
func oneOfEach() *Report {
	return &Report{
		IAM:     []cloud.Finding{{Severity: cloud.SeverityHigh, Type: cloud.FindingAdminAccess, Provider: "aws", Detail: "admin"}},
		Storage: []cloud.BucketFinding{{Severity: cloud.SeverityHigh, Type: cloud.BucketPublicAccess, Provider: "aws", Bucket: "docs"}},
		Network: []cloud.NetworkFinding{{Severity: cloud.SeverityHigh, Type: cloud.NetworkAdminPortOpen, Provider: "aws", Resource: "sg-1"}},
		Secrets: []cloud.SecretFinding{{Severity: cloud.SeverityCritical, Type: cloud.SecretAWSAccessKey, Provider: "aws", Resource: "fn-1", Detail: "AKIA**** in LAMBDA_ENV"}},
		Certs:   []cloud.CertFinding{{Severity: cloud.SeverityCritical, Status: cloud.CertExpired, Provider: "aws", Domain: "api.example.test"}},
		Tags:    []cloud.TagFinding{{Severity: cloud.SeverityMedium, Provider: "aws", ResourceID: "raw", MissingTags: []string{"Team", "Environment"}}},
		Orphans: []cloud.OrphanResource{{Kind: cloud.OrphanDisk, Provider: "aws", ID: "vol-1", MonthlyCost: 8}},
	}
}

// Every domain the report declares must be able to appear in a digest.
//
// The defect this closes: the digest walked four of seven domains while claiming
// "all domains". A sink digest is the whole signal on the unattended path — the
// terminal has nobody reading it — so a run could report Critical: 1 with certs
// among its domains and no certificate in the examples.
//
// Counting the Report's own fields rather than a written list is what makes this
// a class: a domain added to Report and not to TopFindings fails here.
func TestTopFindingsCoversEveryDomainTheReportDeclares(t *testing.T) {
	report := oneOfEach()

	domainFields := 0
	rt := reflect.TypeOf(*report)
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if field.Type.Kind() == reflect.Slice && field.Name != "Incomplete" {
			domainFields++
		}
	}
	if domainFields == 0 {
		t.Fatal("Report declares no finding slices; this check would pass vacuously")
	}

	examples := report.TopFindings(100)
	if len(examples) != domainFields {
		t.Fatalf("Report declares %d finding domains and the digest produced %d examples; "+
			"a domain the walk misses is a finding a digest can never show", domainFields, len(examples))
	}

	// Each example must carry enough to recognise the thing.
	for _, e := range examples {
		if e.Severity == "" || e.Type == "" {
			t.Errorf("an example carries no severity or type, so a reader cannot tell what it is: %+v", e)
		}
		if e.Resource == "" && e.Detail == "" {
			t.Errorf("an example names neither a resource nor a detail: %+v", e)
		}
	}
}

// The digest is severity-ordered, so the n it returns are the n worst rather than
// the n that happen to come first in the domain walk.
func TestTopFindingsReturnsTheWorstFirst(t *testing.T) {
	examples := oneOfEach().TopFindings(2)
	if len(examples) != 2 {
		t.Fatalf("got %d examples, want 2", len(examples))
	}
	for _, e := range examples {
		if e.Severity != string(cloud.SeverityCritical) {
			t.Errorf("a truncated digest returned %s ahead of a CRITICAL finding", e.Severity)
		}
	}
}

func TestTopFindingsHandlesEmptyAndZero(t *testing.T) {
	if got := (&Report{}).TopFindings(5); len(got) != 0 {
		t.Errorf("an empty report produced %d examples", len(got))
	}
	if got := oneOfEach().TopFindings(0); len(got) != 0 {
		t.Errorf("a zero limit produced %d examples", len(got))
	}
	var nilReport *Report
	if got := nilReport.TopFindings(5); len(got) != 0 {
		t.Errorf("a nil report produced %d examples", len(got))
	}
}

// A tag finding's value to a reader is which tags are missing, so the digest
// carries them rather than an empty detail.
func TestTopFindingsNamesTheMissingTags(t *testing.T) {
	report := &Report{Tags: []cloud.TagFinding{
		{Severity: cloud.SeverityMedium, ResourceID: "raw", MissingTags: []string{"Team", "Environment"}},
	}}
	examples := report.TopFindings(1)
	if len(examples) != 1 {
		t.Fatalf("got %d examples, want 1", len(examples))
	}
	if examples[0].Detail != "missing Team, Environment" {
		t.Errorf("detail = %q, want the missing tag list", examples[0].Detail)
	}
}
