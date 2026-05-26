package gcp

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	bigqueryv2 "google.golang.org/api/bigquery/v2"
)

type mockBigQuery struct {
	// rows is keyed by the period's start date. The mock matches on
	// `>= 'DATE'` so adjacent windows (where one period's end equals the
	// next period's start) don't collide.
	rows map[string][]*bigqueryv2.TableRow
	err  error
}

func (m *mockBigQuery) Query(_ context.Context, _, query string) ([]*bigqueryv2.TableRow, error) {
	if m.err != nil {
		return nil, m.err
	}
	for date, v := range m.rows {
		if contains(query, ">= '"+date+"'") {
			return v, nil
		}
	}
	return nil, nil
}

func bqRow(service, amount, currency string) *bigqueryv2.TableRow {
	return &bigqueryv2.TableRow{F: []*bigqueryv2.TableCell{
		{V: service}, {V: amount}, {V: currency},
	}}
}

func TestGCPGetCostDiff_RequiresBillingAccountID(t *testing.T) {
	os.Unsetenv("GOOGLE_BILLING_ACCOUNT_ID")
	p := &Provider{projectID: "p", bigquery: &mockBigQuery{}}
	_, err := p.GetCostDiff(context.Background(), time.Now(), time.Now(), time.Now(), time.Now())
	if err == nil {
		t.Fatal("expected error for missing billing account ID")
	}
}

func TestGCPGetCostDiff_RequiresProjectID(t *testing.T) {
	t.Setenv("GOOGLE_BILLING_ACCOUNT_ID", "ABCDEF-123456-789012")
	p := &Provider{projectID: "", bigquery: &mockBigQuery{}}
	_, err := p.GetCostDiff(context.Background(), time.Now(), time.Now(), time.Now(), time.Now())
	if err == nil {
		t.Fatal("expected error for missing project ID")
	}
}

func TestGCPGetCostDiff_HappyPath(t *testing.T) {
	t.Setenv("GOOGLE_BILLING_ACCOUNT_ID", "ABCDEF-123456-789012")
	before := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	beforeEnd := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	afterEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	p := &Provider{projectID: "my-project", bigquery: &mockBigQuery{
		rows: map[string][]*bigqueryv2.TableRow{
			"2026-04-01": {bqRow("Compute Engine", "100.00", "USD")},
			"2026-05-01": {bqRow("Compute Engine", "150.00", "USD"), bqRow("Cloud Storage", "10.00", "USD")},
		},
	}}
	diff, err := p.GetCostDiff(context.Background(), before, beforeEnd, after, afterEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff.Provider != "gcp" {
		t.Errorf("provider: got %q", diff.Provider)
	}
	if diff.TotalBefore != 100.0 || diff.TotalAfter != 160.0 {
		t.Errorf("totals: before=%v after=%v", diff.TotalBefore, diff.TotalAfter)
	}
}

func TestGCPGetCostDiff_QueryError(t *testing.T) {
	t.Setenv("GOOGLE_BILLING_ACCOUNT_ID", "ABCDEF-123456-789012")
	p := &Provider{projectID: "p", bigquery: &mockBigQuery{err: errors.New("auth")}}
	_, err := p.GetCostDiff(context.Background(), time.Now(), time.Now(), time.Now(), time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}
