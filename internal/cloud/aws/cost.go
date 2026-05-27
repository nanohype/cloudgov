package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// costExplorerAPI is the narrow Cost Explorer surface used by this package.
type costExplorerAPI interface {
	GetCostAndUsage(ctx context.Context, params *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

// GetCostDiff fetches blended cost grouped by service for two time windows and
// computes the per-service delta.
func (p *Provider) GetCostDiff(ctx context.Context, beforeStart, beforeEnd, afterStart, afterEnd time.Time) (cloud.CostDiff, error) {
	before, err := p.fetchCosts(ctx, beforeStart, beforeEnd)
	if err != nil {
		return cloud.CostDiff{}, fmt.Errorf("fetch before period: %w", err)
	}
	after, err := p.fetchCosts(ctx, afterStart, afterEnd)
	if err != nil {
		return cloud.CostDiff{}, fmt.Errorf("fetch after period: %w", err)
	}

	// Index before amounts by service
	beforeMap := make(map[string]float64)
	var totalBefore float64
	for _, e := range before {
		beforeMap[e.Service] = e.Amount
		totalBefore += e.Amount
	}

	// Build diff entries; union of services from both periods
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
		b := beforeMap[svc]
		a := afterMap[svc]
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
		Provider:    "aws",
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

func (p *Provider) fetchCosts(ctx context.Context, start, end time.Time) ([]cloud.CostEntry, error) {
	out, err := p.costexplorer.GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
		TimePeriod: &cetypes.DateInterval{
			Start: awssdk.String(start.Format("2006-01-02")),
			End:   awssdk.String(end.Format("2006-01-02")),
		},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"BlendedCost"},
		GroupBy: []cetypes.GroupDefinition{{
			Type: cetypes.GroupDefinitionTypeDimension,
			Key:  awssdk.String("SERVICE"),
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("get cost and usage: %w", err)
	}

	var entries []cloud.CostEntry
	for _, result := range out.ResultsByTime {
		for _, group := range result.Groups {
			if len(group.Keys) == 0 {
				continue
			}
			svc := group.Keys[0]
			metric, ok := group.Metrics["BlendedCost"]
			if !ok {
				continue
			}
			amount, _ := strconv.ParseFloat(awssdk.ToString(metric.Amount), 64)
			unit := awssdk.ToString(metric.Unit)
			entries = append(entries, cloud.CostEntry{
				Service: svc,
				Amount:  amount,
				Unit:    unit,
			})
		}
	}
	return entries, nil
}
