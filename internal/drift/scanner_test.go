package drift

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockDriftProvider struct {
	name      string
	supported []string
	results   map[string]cloud.DriftResult
	err       error
}

func (m *mockDriftProvider) Name() string                  { return m.name }
func (m *mockDriftProvider) Detect(_ context.Context) bool { return true }
func (m *mockDriftProvider) SupportedResourceTypes() []string {
	return m.supported
}
func (m *mockDriftProvider) CheckDrift(_ context.Context, resourceType, resourceID string, _ map[string]interface{}) (cloud.DriftResult, error) {
	if m.err != nil {
		return cloud.DriftResult{}, m.err
	}
	if r, ok := m.results[resourceID]; ok {
		return r, nil
	}
	return cloud.DriftResult{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func TestScan(t *testing.T) {
	resources := []ParsedResource{
		{Address: "aws_security_group.web", Type: "aws_security_group", Provider: "aws", ID: "sg-1", Attributes: map[string]interface{}{"id": "sg-1"}},
		{Address: "aws_security_group.api", Type: "aws_security_group", Provider: "aws", ID: "sg-2", Attributes: map[string]interface{}{"id": "sg-2"}},
	}

	provider := &mockDriftProvider{
		name:      "aws",
		supported: []string{"aws_security_group"},
		results: map[string]cloud.DriftResult{
			"sg-1": {ResourceType: "aws_security_group", ResourceID: "sg-1", Status: cloud.DriftModified,
				Fields: []cloud.DriftField{{Field: "description", Expected: "old", Actual: "new"}}},
			"sg-2": {ResourceType: "aws_security_group", ResourceID: "sg-2", Status: cloud.DriftInSync},
		},
	}

	results, err := Scan(context.Background(), resources, []cloud.DriftProvider{provider}, ScanOptions{Concurrency: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	// Modified should sort before InSync
	if results[0].Status != cloud.DriftModified {
		t.Errorf("first result status: got %s, want MODIFIED", results[0].Status)
	}
	if results[1].Status != cloud.DriftInSync {
		t.Errorf("second result status: got %s, want IN_SYNC", results[1].Status)
	}
}

func TestScanResourceTypeFilter(t *testing.T) {
	resources := []ParsedResource{
		{Address: "aws_security_group.web", Type: "aws_security_group", Provider: "aws", ID: "sg-1", Attributes: map[string]interface{}{}},
		{Address: "aws_s3_bucket.data", Type: "aws_s3_bucket", Provider: "aws", ID: "data-bucket", Attributes: map[string]interface{}{}},
	}

	provider := &mockDriftProvider{
		name:      "aws",
		supported: []string{"aws_security_group", "aws_s3_bucket"},
	}

	results, err := Scan(context.Background(), resources, []cloud.DriftProvider{provider}, ScanOptions{
		ResourceType: "aws_security_group",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].ResourceName != "aws_security_group.web" {
		t.Errorf("got address %q, want aws_security_group.web", results[0].ResourceName)
	}
}

func TestScanUnsupportedResourceTypeSkipped(t *testing.T) {
	resources := []ParsedResource{
		{Address: "aws_unknown.foo", Type: "aws_unknown", Provider: "aws", ID: "x-1", Attributes: map[string]interface{}{}},
	}

	provider := &mockDriftProvider{
		name:      "aws",
		supported: []string{"aws_security_group"},
	}

	results, err := Scan(context.Background(), resources, []cloud.DriftProvider{provider}, ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("got %d results, want 0", len(results))
	}
}

func TestScanProviderError(t *testing.T) {
	resources := []ParsedResource{
		{Address: "aws_security_group.web", Type: "aws_security_group", Provider: "aws", ID: "sg-1", Attributes: map[string]interface{}{}},
	}

	provider := &mockDriftProvider{
		name:      "aws",
		supported: []string{"aws_security_group"},
		err:       errors.New("api error"),
	}

	results, err := Scan(context.Background(), resources, []cloud.DriftProvider{provider}, ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Status != cloud.DriftError {
		t.Errorf("got status %s, want ERROR", results[0].Status)
	}
}

func TestScanEmptyResources(t *testing.T) {
	results, err := Scan(context.Background(), nil, nil, ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("got %d results, want 0", len(results))
	}
}

// A scan denied every Describe call must not be indistinguishable from a scan
// that found a tfstate matching its account. Every DriftError row reaches the
// incomplete list, which is what carries exit 3 and the JSON report's
// `incomplete` array.
func TestIncompleteReportsEveryUnreadResource(t *testing.T) {
	resources := []ParsedResource{
		{Address: "aws_security_group.web", Type: "aws_security_group", Provider: "aws", ID: "sg-1"},
		{Address: "aws_security_group.api", Type: "aws_security_group", Provider: "aws", ID: "sg-2"},
	}
	provider := &mockDriftProvider{
		name:      "aws",
		supported: []string{"aws_security_group"},
		err:       errors.New("AccessDenied: not authorized to perform ec2:DescribeSecurityGroups"),
	}

	results, err := Scan(context.Background(), resources, []cloud.DriftProvider{provider}, ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	incomplete := Incomplete(results)
	if len(incomplete) != len(resources) {
		t.Fatalf("Incomplete returned %d entries for %d unread resources: %v", len(incomplete), len(resources), incomplete)
	}
	for _, entry := range incomplete {
		if !strings.Contains(entry, "AccessDenied") {
			t.Errorf("incomplete entry does not carry the reason the read failed: %q", entry)
		}
	}
}

// A resource that was read is not an incomplete observation, whether it matched
// its state or drifted from it.
func TestIncompleteIgnoresObservedResources(t *testing.T) {
	for _, status := range []cloud.DriftStatus{cloud.DriftInSync, cloud.DriftModified, cloud.DriftDeleted} {
		t.Run(string(status), func(t *testing.T) {
			got := Incomplete([]cloud.DriftResult{{ResourceType: "aws_security_group", ResourceID: "sg-1", Status: status}})
			if len(got) != 0 {
				t.Errorf("Incomplete reported an observed %s resource: %v", status, got)
			}
		})
	}
}
