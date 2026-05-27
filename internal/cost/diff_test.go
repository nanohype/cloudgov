package cost

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockCostProvider struct {
	name string
	diff cloud.CostDiff
	err  error
}

func (m *mockCostProvider) Name() string                  { return m.name }
func (m *mockCostProvider) Detect(_ context.Context) bool { return true }
func (m *mockCostProvider) GetCostDiff(_ context.Context, _, _, _, _ time.Time) (cloud.CostDiff, error) {
	if m.err != nil {
		return cloud.CostDiff{}, m.err
	}
	return m.diff, nil
}

func TestScan(t *testing.T) {
	entries := []cloud.CostDiffEntry{
		{Service: "S3", Delta: 5, PctChange: 10},
		{Service: "EC2", Delta: -50, PctChange: -25},
		{Service: "Lambda", Delta: 100, PctChange: 200},
	}
	p := &mockCostProvider{name: "aws", diff: cloud.CostDiff{Provider: "aws", Entries: entries}}

	got, err := Scan(context.Background(), []cloud.CostProvider{p}, ScanOptions{Days: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(got))
	}
	// Sorted by abs(Delta) descending
	if got[0].Entries[0].Service != "Lambda" {
		t.Errorf("expected Lambda (100) first, got %s", got[0].Entries[0].Service)
	}
	if got[0].Entries[1].Service != "EC2" {
		t.Errorf("expected EC2 (50) second, got %s", got[0].Entries[1].Service)
	}
	if got[0].Entries[2].Service != "S3" {
		t.Errorf("expected S3 (5) third, got %s", got[0].Entries[2].Service)
	}
}

func TestScan_ThresholdFilter(t *testing.T) {
	entries := []cloud.CostDiffEntry{
		{Service: "Big", PctChange: 50, Delta: 100},
		{Service: "Small", PctChange: 5, Delta: 10},
	}
	p := &mockCostProvider{name: "aws", diff: cloud.CostDiff{Entries: entries}}

	got, _ := Scan(context.Background(), []cloud.CostProvider{p}, ScanOptions{Days: 30, Threshold: 20})
	if len(got[0].Entries) != 1 || got[0].Entries[0].Service != "Big" {
		t.Errorf("expected only Big (>20%% change), got %v", got[0].Entries)
	}
}

func TestScan_ProviderError(t *testing.T) {
	p := &mockCostProvider{name: "aws", err: errors.New("auth")}
	_, err := Scan(context.Background(), []cloud.CostProvider{p}, ScanOptions{Days: 30})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestScan_MultipleProviders(t *testing.T) {
	aws := &mockCostProvider{name: "aws", diff: cloud.CostDiff{Provider: "aws"}}
	gcp := &mockCostProvider{name: "gcp", diff: cloud.CostDiff{Provider: "gcp"}}
	got, err := Scan(context.Background(), []cloud.CostProvider{aws, gcp}, ScanOptions{Days: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 diffs, got %d", len(got))
	}
}
