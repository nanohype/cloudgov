package azure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/costmanagement/armcostmanagement"
)

type mockCostQuery struct {
	results map[string]armcostmanagement.QueryResult // keyed by date
	err     error
	calls   int
}

func (m *mockCostQuery) Usage(_ context.Context, _ string, def armcostmanagement.QueryDefinition) (armcostmanagement.QueryResult, error) {
	m.calls++
	if m.err != nil {
		return armcostmanagement.QueryResult{}, m.err
	}
	if def.TimePeriod != nil && def.TimePeriod.From != nil {
		key := def.TimePeriod.From.Format("2006-01-02")
		if r, ok := m.results[key]; ok {
			return r, nil
		}
	}
	return armcostmanagement.QueryResult{}, nil
}

func bqRow(amount float64, currency, service string) []any {
	return []any{amount, currency, service}
}

func TestGetCostDiff(t *testing.T) {
	before := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	beforeEnd := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	afterEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	p := &Provider{subscriptionID: "sub-1", costQuery: &mockCostQuery{
		results: map[string]armcostmanagement.QueryResult{
			"2026-04-01": {Properties: &armcostmanagement.QueryProperties{Rows: [][]any{
				bqRow(100.0, "USD", "Compute"),
				bqRow(50.0, "USD", "Storage"),
			}}},
			"2026-05-01": {Properties: &armcostmanagement.QueryProperties{Rows: [][]any{
				bqRow(150.0, "USD", "Compute"),
				bqRow(25.0, "USD", "Storage"),
			}}},
		},
	}}
	diff, err := p.GetCostDiff(context.Background(), before, beforeEnd, after, afterEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff.Provider != "azure" {
		t.Errorf("provider: got %q", diff.Provider)
	}
	if diff.TotalBefore != 150 || diff.TotalAfter != 175 {
		t.Errorf("totals wrong: %+v", diff)
	}
	if len(diff.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(diff.Entries))
	}
}

func TestGetCostDiff_BeforeError(t *testing.T) {
	p := &Provider{costQuery: &mockCostQuery{err: errors.New("auth")}}
	_, err := p.GetCostDiff(context.Background(), time.Now(), time.Now(), time.Now(), time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestToPtr(t *testing.T) {
	s := "hello"
	p := toPtr(s)
	if *p != s {
		t.Errorf("toPtr broken")
	}
	_ = to.Ptr("compile-check")
}
