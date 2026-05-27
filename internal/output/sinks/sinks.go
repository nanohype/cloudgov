// Package sinks ships scan-completion notifications to external systems.
//
// A Sink converts an audit Digest into a payload its target expects and
// POSTs it. Concrete sinks: WebhookSink (generic JSON), SlackSink (incoming-
// webhook JSON), PagerDutySink (Events API v2).
//
// CLI integration: commands accept a repeatable --sink flag with the form
// "<kind>:<url-or-key>" (e.g. "slack:https://hooks.slack.com/services/...").
// Parse() builds Sinks from those specs; SendAll() fires them in sequence
// and aggregates errors so one bad sink doesn't block the others.
package sinks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Digest is the canonical payload format passed to every Sink. Sinks adapt
// it to whatever the target system expects.
type Digest struct {
	Source        string // "matlock audit" / "matlock iam scan"
	Provider      string // "aws" / "gcp" / "azure" / "multi"
	Timestamp     time.Time
	TotalFindings int
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int
	Domains       []string  // ["iam", "storage", "network", ...]
	Top           []Finding // bounded list (typically top 10) for inline display
	ReportURL     string    // optional link to full report
}

// Finding is a per-issue line for inclusion in the digest body.
type Finding struct {
	Severity string
	Type     string
	Provider string
	Resource string
	Detail   string
}

// WorstSeverity returns the highest severity present in this digest.
func (d Digest) WorstSeverity() string {
	switch {
	case d.Critical > 0:
		return "CRITICAL"
	case d.High > 0:
		return "HIGH"
	case d.Medium > 0:
		return "MEDIUM"
	case d.Low > 0:
		return "LOW"
	default:
		return "INFO"
	}
}

// Sink delivers a Digest to one external destination.
type Sink interface {
	Name() string
	Send(ctx context.Context, d Digest) error
}

// Parse turns CLI-friendly specs like "slack:https://hooks.slack.com/..."
// or "webhook:https://example.com/hook" into concrete Sinks.
//
// Forms accepted:
//
//	slack:<webhook-url>
//	webhook:<url>
//	pagerduty:<routing-key>
//
// "<kind>:" prefix is required so the parse stays unambiguous when URLs
// themselves contain colons.
func Parse(specs []string) ([]Sink, error) {
	var out []Sink
	for _, spec := range specs {
		s := strings.TrimSpace(spec)
		if s == "" {
			continue
		}
		idx := strings.Index(s, ":")
		if idx < 0 {
			return nil, fmt.Errorf("sink %q: missing kind prefix (want <kind>:<url-or-key>)", spec)
		}
		kind := strings.ToLower(strings.TrimSpace(s[:idx]))
		rest := strings.TrimSpace(s[idx+1:])
		if rest == "" {
			return nil, fmt.Errorf("sink %q: missing url or key after %s:", spec, kind)
		}
		switch kind {
		case "slack":
			out = append(out, &SlackSink{WebhookURL: rest})
		case "webhook":
			out = append(out, &WebhookSink{URL: rest})
		case "pagerduty":
			out = append(out, &PagerDutySink{RoutingKey: rest})
		default:
			return nil, fmt.Errorf("sink %q: unknown kind %q (want slack, webhook, or pagerduty)", spec, kind)
		}
	}
	return out, nil
}

// SendAll fires every sink and aggregates errors. One sink's failure does
// not short-circuit the others — callers typically want best-effort delivery.
func SendAll(ctx context.Context, ss []Sink, d Digest) error {
	var errs []error
	for _, sink := range ss {
		if err := sink.Send(ctx, d); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sink.Name(), err))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}
