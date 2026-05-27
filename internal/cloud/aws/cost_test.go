package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

type mockCostExplorer struct {
	// responses keyed by start date so before/after windows return different data
	responses map[string]*costexplorer.GetCostAndUsageOutput
	err       error
	calls     int
}

func (m *mockCostExplorer) GetCostAndUsage(_ context.Context, in *costexplorer.GetCostAndUsageInput, _ ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	key := awssdk.ToString(in.TimePeriod.Start)
	if out, ok := m.responses[key]; ok {
		return out, nil
	}
	return &costexplorer.GetCostAndUsageOutput{}, nil
}

func costEntry(svc, amount string) cetypes.Group {
	return cetypes.Group{
		Keys: []string{svc},
		Metrics: map[string]cetypes.MetricValue{
			"BlendedCost": {
				Amount: awssdk.String(amount),
				Unit:   awssdk.String("USD"),
			},
		},
	}
}

func TestGetCostDiff(t *testing.T) {
	before := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	beforeEnd := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	afterEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	p := &Provider{costexplorer: &mockCostExplorer{
		responses: map[string]*costexplorer.GetCostAndUsageOutput{
			"2026-04-01": {ResultsByTime: []cetypes.ResultByTime{{
				Groups: []cetypes.Group{
					costEntry("EC2", "100.00"),
					costEntry("S3", "50.00"),
				},
			}}},
			"2026-05-01": {ResultsByTime: []cetypes.ResultByTime{{
				Groups: []cetypes.Group{
					costEntry("EC2", "150.00"),
					costEntry("S3", "25.00"),
					costEntry("Lambda", "10.00"), // new service in after period
				},
			}}},
		},
	}}

	diff, err := p.GetCostDiff(context.Background(), before, beforeEnd, after, afterEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff.Provider != "aws" {
		t.Errorf("provider: got %q", diff.Provider)
	}
	if diff.TotalBefore != 150.00 {
		t.Errorf("total before: got %v, want 150.00", diff.TotalBefore)
	}
	if diff.TotalAfter != 185.00 {
		t.Errorf("total after: got %v, want 185.00", diff.TotalAfter)
	}
	if diff.TotalDelta != 35.00 {
		t.Errorf("total delta: got %v, want 35.00", diff.TotalDelta)
	}
	if len(diff.Entries) != 3 {
		t.Errorf("entries: got %d, want 3 (EC2+S3+Lambda)", len(diff.Entries))
	}

	byService := map[string]cloud_CostDiffEntry{}
	for _, e := range diff.Entries {
		byService[e.Service] = cloud_CostDiffEntry{e.Before, e.After, e.Delta, e.PctChange}
	}
	if e := byService["EC2"]; e.Before != 100 || e.After != 150 || e.Delta != 50 || e.PctChange != 50 {
		t.Errorf("EC2 entry: got %+v", e)
	}
	if e := byService["S3"]; e.Before != 50 || e.After != 25 || e.Delta != -25 || e.PctChange != -50 {
		t.Errorf("S3 entry: got %+v", e)
	}
	if e := byService["Lambda"]; e.Before != 0 || e.After != 10 || e.Delta != 10 || e.PctChange != 0 {
		// PctChange is 0 because Before is 0 (avoids div-by-zero)
		t.Errorf("Lambda entry: got %+v", e)
	}
}

func TestGetCostDiff_BeforeError(t *testing.T) {
	p := &Provider{costexplorer: &mockCostExplorer{err: errors.New("throttled")}}
	_, err := p.GetCostDiff(context.Background(), time.Now(), time.Now(), time.Now(), time.Now())
	if err == nil {
		t.Fatal("expected error from cost explorer")
	}
}

func TestGetCostDiff_EmptyPeriods(t *testing.T) {
	p := &Provider{costexplorer: &mockCostExplorer{}}
	diff, err := p.GetCostDiff(context.Background(), time.Now(), time.Now(), time.Now(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff.TotalBefore != 0 || diff.TotalAfter != 0 {
		t.Errorf("expected zero totals: %+v", diff)
	}
	if len(diff.Entries) != 0 {
		t.Errorf("expected no entries: %v", diff.Entries)
	}
}

// helper struct for table assertions, not part of public API
type cloud_CostDiffEntry struct {
	Before, After, Delta, PctChange float64
}
