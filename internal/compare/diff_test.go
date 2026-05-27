package compare

import (
	"testing"
)

func TestDiff_AllNew(t *testing.T) {
	current := []NormalizedFinding{
		{Provider: "aws", Type: "ADMIN_ACCESS", ResourceID: "role/admin", Detail: "admin"},
		{Provider: "aws", Type: "PUBLIC_ACCESS", ResourceID: "bucket-1", Detail: "public"},
	}

	result := Diff(nil, current)

	if len(result.New) != 2 {
		t.Errorf("New: got %d, want 2", len(result.New))
	}
	if len(result.Resolved) != 0 {
		t.Errorf("Resolved: got %d, want 0", len(result.Resolved))
	}
	if len(result.Unchanged) != 0 {
		t.Errorf("Unchanged: got %d, want 0", len(result.Unchanged))
	}
}

func TestDiff_AllResolved(t *testing.T) {
	baseline := []NormalizedFinding{
		{Provider: "aws", Type: "ADMIN_ACCESS", ResourceID: "role/admin", Detail: "admin"},
		{Provider: "aws", Type: "PUBLIC_ACCESS", ResourceID: "bucket-1", Detail: "public"},
	}

	result := Diff(baseline, nil)

	if len(result.New) != 0 {
		t.Errorf("New: got %d, want 0", len(result.New))
	}
	if len(result.Resolved) != 2 {
		t.Errorf("Resolved: got %d, want 2", len(result.Resolved))
	}
	if len(result.Unchanged) != 0 {
		t.Errorf("Unchanged: got %d, want 0", len(result.Unchanged))
	}
}

func TestDiff_AllUnchanged(t *testing.T) {
	findings := []NormalizedFinding{
		{Provider: "aws", Type: "ADMIN_ACCESS", ResourceID: "role/admin", Detail: "admin"},
	}

	result := Diff(findings, findings)

	if len(result.New) != 0 {
		t.Errorf("New: got %d, want 0", len(result.New))
	}
	if len(result.Resolved) != 0 {
		t.Errorf("Resolved: got %d, want 0", len(result.Resolved))
	}
	if len(result.Unchanged) != 1 {
		t.Errorf("Unchanged: got %d, want 1", len(result.Unchanged))
	}
}

func TestDiff_Mixed(t *testing.T) {
	baseline := []NormalizedFinding{
		{Provider: "aws", Type: "ADMIN_ACCESS", ResourceID: "role/admin", Detail: "admin"},       // will be resolved
		{Provider: "aws", Type: "PUBLIC_ACCESS", ResourceID: "bucket-1", Detail: "public"},        // unchanged
		{Provider: "gcp", Type: "WILDCARD_RESOURCE", ResourceID: "sa-1", Detail: "wildcard"},      // will be resolved
	}

	current := []NormalizedFinding{
		{Provider: "aws", Type: "PUBLIC_ACCESS", ResourceID: "bucket-1", Detail: "public"},        // unchanged
		{Provider: "aws", Type: "UNUSED_PERMISSION", ResourceID: "role/dev", Detail: "unused"},    // new
	}

	result := Diff(baseline, current)

	if len(result.New) != 1 {
		t.Errorf("New: got %d, want 1", len(result.New))
	}
	if len(result.Resolved) != 2 {
		t.Errorf("Resolved: got %d, want 2", len(result.Resolved))
	}
	if len(result.Unchanged) != 1 {
		t.Errorf("Unchanged: got %d, want 1", len(result.Unchanged))
	}

	if result.New[0].Type != "UNUSED_PERMISSION" {
		t.Errorf("New[0].Type = %q, want UNUSED_PERMISSION", result.New[0].Type)
	}
}

func TestDiff_SeverityChangeStillMatches(t *testing.T) {
	baseline := []NormalizedFinding{
		{Provider: "aws", Type: "ADMIN_ACCESS", ResourceID: "role/admin", Detail: "admin", Severity: "HIGH"},
	}
	current := []NormalizedFinding{
		{Provider: "aws", Type: "ADMIN_ACCESS", ResourceID: "role/admin", Detail: "admin", Severity: "CRITICAL"},
	}

	result := Diff(baseline, current)

	if len(result.Unchanged) != 1 {
		t.Errorf("Unchanged: got %d, want 1 (severity change should still match)", len(result.Unchanged))
	}
	if len(result.New) != 0 {
		t.Errorf("New: got %d, want 0", len(result.New))
	}
	if len(result.Resolved) != 0 {
		t.Errorf("Resolved: got %d, want 0", len(result.Resolved))
	}
}

func TestDiff_EmptyInputs(t *testing.T) {
	result := Diff(nil, nil)

	if len(result.New) != 0 {
		t.Errorf("New: got %d, want 0", len(result.New))
	}
	if len(result.Resolved) != 0 {
		t.Errorf("Resolved: got %d, want 0", len(result.Resolved))
	}
	if len(result.Unchanged) != 0 {
		t.Errorf("Unchanged: got %d, want 0", len(result.Unchanged))
	}
}

func TestDiff_EmptyBaseline(t *testing.T) {
	current := []NormalizedFinding{
		{Provider: "aws", Type: "X", ResourceID: "1", Detail: "d"},
	}
	result := Diff([]NormalizedFinding{}, current)

	if len(result.New) != 1 {
		t.Errorf("New: got %d, want 1", len(result.New))
	}
}

func TestDiff_EmptyCurrent(t *testing.T) {
	baseline := []NormalizedFinding{
		{Provider: "aws", Type: "X", ResourceID: "1", Detail: "d"},
	}
	result := Diff(baseline, []NormalizedFinding{})

	if len(result.Resolved) != 1 {
		t.Errorf("Resolved: got %d, want 1", len(result.Resolved))
	}
}
