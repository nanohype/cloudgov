package azure

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/costmanagement/armcostmanagement"
	"github.com/stxkxs/matlock/internal/cloud"
)

// costQueryAPI is the narrow Cost Management Query surface used by this package.
type costQueryAPI interface {
	Usage(ctx context.Context, scope string, def armcostmanagement.QueryDefinition) (armcostmanagement.QueryResult, error)
}

type costQueryAdapter struct {
	client *armcostmanagement.QueryClient
}

func (a *costQueryAdapter) Usage(ctx context.Context, scope string, def armcostmanagement.QueryDefinition) (armcostmanagement.QueryResult, error) {
	resp, err := a.client.Usage(ctx, scope, def, nil)
	if err != nil {
		return armcostmanagement.QueryResult{}, err
	}
	return resp.QueryResult, nil
}

// GetCostDiff queries Azure Cost Management for spend in two periods and diffs them.
func (p *Provider) GetCostDiff(ctx context.Context, beforeStart, beforeEnd, afterStart, afterEnd time.Time) (cloud.CostDiff, error) {
	scope := "/subscriptions/" + p.subscriptionID

	before, err := p.fetchCosts(ctx, scope, beforeStart, beforeEnd)
	if err != nil {
		return cloud.CostDiff{}, fmt.Errorf("fetch before period: %w", err)
	}
	after, err := p.fetchCosts(ctx, scope, afterStart, afterEnd)
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
	for svc := range beforeMap {
		services[svc] = true
	}
	for svc := range afterMap {
		services[svc] = true
	}

	var entries []cloud.CostDiffEntry
	for svc := range services {
		b, a := beforeMap[svc], afterMap[svc]
		delta := a - b
		var pct float64
		if b > 0 {
			pct = (delta / b) * 100
		}
		entries = append(entries, cloud.CostDiffEntry{
			Service:   svc,
			Before:    b,
			After:     a,
			Delta:     delta,
			PctChange: pct,
		})
	}

	return cloud.CostDiff{
		Provider:    "azure",
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

func (p *Provider) fetchCosts(ctx context.Context, scope string, start, end time.Time) ([]cloud.CostEntry, error) {
	timePeriod := &armcostmanagement.QueryTimePeriod{
		From: &start,
		To:   &end,
	}
	grouping := []*armcostmanagement.QueryGrouping{{
		Type: toPtr(armcostmanagement.QueryColumnTypeDimension),
		Name: toPtr("ServiceName"),
	}}
	dataset := &armcostmanagement.QueryDataset{
		Granularity: toPtr(armcostmanagement.GranularityTypeDaily),
		Grouping:    grouping,
		Aggregation: map[string]*armcostmanagement.QueryAggregation{
			"TotalCost": {
				Name:     toPtr("Cost"),
				Function: toPtr(armcostmanagement.FunctionTypeSum),
			},
		},
	}
	out, err := p.costQuery.Usage(ctx, scope, armcostmanagement.QueryDefinition{
		Type:       toPtr(armcostmanagement.ExportTypeActualCost),
		Timeframe:  toPtr(armcostmanagement.TimeframeTypeCustom),
		TimePeriod: timePeriod,
		Dataset:    dataset,
	})
	if err != nil {
		return nil, fmt.Errorf("cost management usage query: %w", err)
	}

	var entries []cloud.CostEntry
	if out.Properties == nil || out.Properties.Rows == nil {
		return entries, nil
	}
	// Rows schema: [Cost, Currency, ServiceName, ...]
	for _, row := range out.Properties.Rows {
		if len(row) < 3 {
			continue
		}
		amount, _ := strconv.ParseFloat(fmt.Sprintf("%v", row[0]), 64)
		svc := fmt.Sprintf("%v", row[2])
		entries = append(entries, cloud.CostEntry{
			Service: svc,
			Amount:  amount,
			Unit:    "USD",
		})
	}
	return entries, nil
}

func toPtr[T any](v T) *T { return &v }
