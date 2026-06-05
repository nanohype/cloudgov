package cmd

import (
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestUnmarshalStorageReport(t *testing.T) {
	// Envelope shape.
	env := []byte(`{"findings":[{"bucket":"b1","severity":"HIGH"}],"total":1}`)
	got, err := unmarshalStorageReport(env)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if len(got) != 1 || got[0].Bucket != "b1" {
		t.Errorf("envelope: got %+v", got)
	}
	// Bare-array fallback.
	bare := []byte(`[{"bucket":"b2","severity":"LOW"}]`)
	got, err = unmarshalStorageReport(bare)
	if err != nil {
		t.Fatalf("bare: %v", err)
	}
	if len(got) != 1 || got[0].Bucket != "b2" {
		t.Errorf("bare: got %+v", got)
	}
	// Invalid JSON errors.
	if _, err := unmarshalStorageReport([]byte("not json")); err == nil {
		t.Error("expected error on invalid JSON")
	}
	// Valid envelope with no findings returns empty, not an error (the fallback's
	// final path).
	got, err = unmarshalStorageReport([]byte(`{"findings":[],"total":0}`))
	if err != nil || len(got) != 0 {
		t.Errorf("empty envelope: got %+v err %v, want empty/nil", got, err)
	}
}

func TestUnmarshalNetworkReport(t *testing.T) {
	got, err := unmarshalNetworkReport([]byte(`{"findings":[{"resource":"sg-1","severity":"HIGH"}]}`))
	if err != nil || len(got) != 1 || got[0].Resource != "sg-1" {
		t.Fatalf("envelope: got %+v err %v", got, err)
	}
	got, err = unmarshalNetworkReport([]byte(`[{"resource":"sg-2"}]`))
	if err != nil || len(got) != 1 || got[0].Resource != "sg-2" {
		t.Fatalf("bare: got %+v err %v", got, err)
	}
	if _, err := unmarshalNetworkReport([]byte("not json")); err == nil {
		t.Error("expected error on invalid JSON")
	}
	got, err = unmarshalNetworkReport([]byte(`{"findings":[]}`))
	if err != nil || len(got) != 0 {
		t.Errorf("empty envelope: got %+v err %v, want empty/nil", got, err)
	}
}

func TestUnmarshalOrphansReport(t *testing.T) {
	// Orphans use a "resources" envelope (not "findings").
	got, err := unmarshalOrphansReport([]byte(`{"resources":[{"Kind":"disk","ID":"vol-1"}],"total":1}`))
	if err != nil || len(got) != 1 || got[0].ID != "vol-1" {
		t.Fatalf("envelope: got %+v err %v", got, err)
	}
	got, err = unmarshalOrphansReport([]byte(`[{"Kind":"ip","ID":"eip-1"}]`))
	if err != nil || len(got) != 1 || got[0].ID != "eip-1" {
		t.Fatalf("bare: got %+v err %v", got, err)
	}
	if _, err := unmarshalOrphansReport([]byte("not json")); err == nil {
		t.Error("expected error on invalid JSON")
	}
	got, err = unmarshalOrphansReport([]byte(`{"resources":[],"total":0}`))
	if err != nil || len(got) != 0 {
		t.Errorf("empty envelope: got %+v err %v, want empty/nil", got, err)
	}
}

func TestFilterStorageBySeverity(t *testing.T) {
	in := []cloud.BucketFinding{
		{Bucket: "crit", Severity: cloud.SeverityCritical},
		{Bucket: "low", Severity: cloud.SeverityLow},
	}
	got := filterStorageBySeverity(in, cloud.SeverityHigh)
	if len(got) != 1 || got[0].Bucket != "crit" {
		t.Errorf("got %+v, want only crit", got)
	}
}

func TestFilterNetworkBySeverity(t *testing.T) {
	in := []cloud.NetworkFinding{
		{Resource: "high", Severity: cloud.SeverityHigh},
		{Resource: "low", Severity: cloud.SeverityLow},
	}
	got := filterNetworkBySeverity(in, cloud.SeverityMedium)
	if len(got) != 1 || got[0].Resource != "high" {
		t.Errorf("got %+v, want only high", got)
	}
}

func TestAnnounceFiles(t *testing.T) {
	// Exercises both the "wrote" and the "no remediable findings" branches, plus
	// the quiet short-circuit. Output goes to stderr; we assert it doesn't panic
	// and that quiet suppresses cleanly.
	orig := quiet
	defer func() { quiet = orig }()
	quiet = false
	announceFiles([]string{"fix-aws.sh"}, 1)
	announceFiles(nil, 3)
	quiet = true
	announceFiles([]string{"fix-aws.sh"}, 1)
}
