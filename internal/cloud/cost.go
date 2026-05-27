package cloud

import (
	"context"
	"time"
)

// CostEntry is the spend for one service in a time window.
type CostEntry struct {
	Service string
	Amount  float64
	Unit    string
}

// CostPeriod holds the cost breakdown for a time range.
type CostPeriod struct {
	Start   time.Time
	End     time.Time
	Entries []CostEntry
	Total   float64
}

// CostDiffEntry is the per-service delta between two periods.
type CostDiffEntry struct {
	Service   string
	Before    float64
	After     float64
	Delta     float64
	PctChange float64
}

// CostDiff is the full comparison between two billing periods.
type CostDiff struct {
	Provider    string
	BeforeStart time.Time
	BeforeEnd   time.Time
	AfterStart  time.Time
	AfterEnd    time.Time
	Entries     []CostDiffEntry
	TotalBefore float64
	TotalAfter  float64
	TotalDelta  float64
}

// CostProvider fetches billing data and computes diffs.
type CostProvider interface {
	Provider
	GetCostDiff(ctx context.Context, beforeStart, beforeEnd, afterStart, afterEnd time.Time) (CostDiff, error)
}
