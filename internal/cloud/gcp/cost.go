package gcp

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	bigqueryv2 "google.golang.org/api/bigquery/v2"

	"github.com/stxkxs/matlock/internal/cloud"
)

// bigqueryAPI is the narrow BigQuery surface used by this package.
type bigqueryAPI interface {
	Query(ctx context.Context, projectID, query string) ([]*bigqueryv2.TableRow, error)
}

type bigqueryAdapter struct{ svc *bigqueryv2.Service }

func (a *bigqueryAdapter) Query(ctx context.Context, projectID, query string) ([]*bigqueryv2.TableRow, error) {
	useLegacySQL := false
	resp, err := a.svc.Jobs.Query(projectID, &bigqueryv2.QueryRequest{
		Query:        query,
		UseLegacySql: &useLegacySQL,
		TimeoutMs:    60000,
	}).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Rows, nil
}

// GetCostDiff queries GCP billing export data via BigQuery for two time windows
// and computes the per-service cost delta.
//
// Required env vars:
//   - GOOGLE_BILLING_ACCOUNT_ID — GCP billing account ID (e.g. ABCDEF-123456-789012)
//   - GOOGLE_CLOUD_PROJECT — GCP project containing the BigQuery billing export
//
// Optional env vars:
//   - GOOGLE_BIGQUERY_BILLING_DATASET — BigQuery dataset name (default: billing)
func (p *Provider) GetCostDiff(ctx context.Context, beforeStart, beforeEnd, afterStart, afterEnd time.Time) (cloud.CostDiff, error) {
	billingAccountID := os.Getenv("GOOGLE_BILLING_ACCOUNT_ID")
	if billingAccountID == "" {
		return cloud.CostDiff{}, fmt.Errorf("GCP cost diff requires GOOGLE_BILLING_ACCOUNT_ID env var " +
			"(e.g. ABCDEF-123456-789012); also set GOOGLE_BIGQUERY_BILLING_DATASET if your billing " +
			"export dataset is not named 'billing'")
	}

	if p.projectID == "" {
		return cloud.CostDiff{}, fmt.Errorf("GCP cost diff requires GOOGLE_CLOUD_PROJECT env var " +
			"(the project that contains your BigQuery billing export)")
	}

	dataset := os.Getenv("GOOGLE_BIGQUERY_BILLING_DATASET")
	if dataset == "" {
		dataset = "billing"
	}

	// Standard GCP billing export table name uses underscores in place of dashes.
	tableID := "gcp_billing_export_v1_" + strings.ReplaceAll(billingAccountID, "-", "_")

	before, err := p.fetchBQCosts(ctx, p.projectID, dataset, tableID, beforeStart, beforeEnd)
	if err != nil {
		return cloud.CostDiff{}, fmt.Errorf("fetch before period: %w", err)
	}
	after, err := p.fetchBQCosts(ctx, p.projectID, dataset, tableID, afterStart, afterEnd)
	if err != nil {
		return cloud.CostDiff{}, fmt.Errorf("fetch after period: %w", err)
	}

	beforeMap := make(map[string]float64)
	var totalBefore float64
	for _, e := range before {
		beforeMap[e.Service] = e.Amount
		totalBefore += e.Amount
	}

	afterMap := make(map[string]float64)
	var totalAfter float64
	for _, e := range after {
		afterMap[e.Service] = e.Amount
		totalAfter += e.Amount
	}

	services := make(map[string]bool)
	for name := range beforeMap {
		services[name] = true
	}
	for name := range afterMap {
		services[name] = true
	}

	var entries []cloud.CostDiffEntry
	for name := range services {
		b, a := beforeMap[name], afterMap[name]
		delta := a - b
		var pct float64
		if b > 0 {
			pct = (delta / b) * 100
		}
		entries = append(entries, cloud.CostDiffEntry{
			Service:   name,
			Before:    b,
			After:     a,
			Delta:     delta,
			PctChange: pct,
		})
	}

	return cloud.CostDiff{
		Provider:    "gcp",
		BeforeStart: beforeStart,
		BeforeEnd:   beforeEnd,
		AfterStart:  afterStart,
		AfterEnd:    afterEnd,
		Entries:     entries,
		TotalBefore: totalBefore,
		TotalAfter:  totalAfter,
		TotalDelta:  totalAfter - totalBefore,
	}, nil
}

func (p *Provider) fetchBQCosts(ctx context.Context, projectID, dataset, tableID string, start, end time.Time) ([]cloud.CostEntry, error) {
	// Columns returned: service (string), total_cost (float), currency (string)
	query := fmt.Sprintf(
		"SELECT service.description AS service, SUM(cost) AS total_cost, currency "+
			"FROM `%s.%s.%s` "+
			"WHERE DATE(usage_start_time) >= '%s' AND DATE(usage_start_time) < '%s' "+
			"GROUP BY service, currency "+
			"ORDER BY total_cost DESC",
		projectID, dataset, tableID,
		start.Format("2006-01-02"),
		end.Format("2006-01-02"),
	)

	rows, err := p.bigquery.Query(ctx, projectID, query)
	if err != nil {
		return nil, fmt.Errorf("bigquery query: %w", err)
	}

	var entries []cloud.CostEntry
	for _, row := range rows {
		if len(row.F) < 3 {
			continue
		}
		service := fmt.Sprintf("%v", row.F[0].V)
		amountStr := fmt.Sprintf("%v", row.F[1].V)
		currency := fmt.Sprintf("%v", row.F[2].V)
		amount, _ := strconv.ParseFloat(amountStr, 64)
		entries = append(entries, cloud.CostEntry{
			Service: service,
			Amount:  amount,
			Unit:    currency,
		})
	}
	return entries, nil
}
