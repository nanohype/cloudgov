package cloud

import "context"

// QuotaUsage represents a single service quota and its current utilization.
type QuotaUsage struct {
	Provider    string   `json:"provider"`
	Service     string   `json:"service"`
	QuotaName   string   `json:"quota_name"`
	Used        float64  `json:"used"`
	Limit       float64  `json:"limit"`
	Utilization float64  `json:"utilization"`
	Region      string   `json:"region"`
	Severity    Severity `json:"severity"`
}

// EffectiveSeverity returns the stored Severity, falling back to computing it from
// Utilization when unset — e.g. a report saved before Severity was a field, or a
// QuotaUsage built without going through a provider's ListQuotas.
func (q QuotaUsage) EffectiveSeverity() Severity {
	if q.Severity != "" {
		return q.Severity
	}
	return QuotaSeverity(q.Utilization)
}

// QuotaProvider lists service quota utilization.
type QuotaProvider interface {
	Provider
	ListQuotas(ctx context.Context) ([]QuotaUsage, error)
}

// QuotaSeverity returns a severity based on utilization percentage.
func QuotaSeverity(utilization float64) Severity {
	switch {
	case utilization >= 90:
		return SeverityCritical
	case utilization >= 80:
		return SeverityHigh
	case utilization >= 50:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
