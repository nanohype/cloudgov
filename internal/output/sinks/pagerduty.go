package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const pdEventsAPIURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDutySink fires an Events API v2 trigger when the digest has any
// critical or high findings. Medium-and-below scans are dropped to avoid
// alert fatigue. Routing happens via the integration key (one per service).
type PagerDutySink struct {
	RoutingKey string
	// URL overrides the API endpoint (used in tests).
	URL string
	// HTTPClient is optional; defaults to a 10-second-timeout client.
	HTTPClient *http.Client
}

func (s *PagerDutySink) Name() string { return "pagerduty" }

func (s *PagerDutySink) Send(ctx context.Context, d Digest) error {
	if s.RoutingKey == "" {
		return fmt.Errorf("pagerduty: routing key is required")
	}

	// PagerDuty incidents should be high-signal — only page on critical/high.
	if d.Critical == 0 && d.High == 0 {
		return nil
	}

	severity := strings.ToLower(d.WorstSeverity())
	if severity != "critical" {
		severity = "error" // PagerDuty severities: critical, error, warning, info
	}

	payload := map[string]interface{}{
		"routing_key":  s.RoutingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("matlock-%s-%s", d.Source, d.Provider),
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("%s: %d findings on %s (%d critical, %d high)", d.Source, d.TotalFindings, d.Provider, d.Critical, d.High),
			"source":    d.Source,
			"severity":  severity,
			"timestamp": d.Timestamp.UTC().Format(time.RFC3339),
			"component": d.Provider,
			"group":     "matlock",
			"class":     strings.Join(d.Domains, ","),
			"custom_details": map[string]interface{}{
				"critical": d.Critical,
				"high":     d.High,
				"medium":   d.Medium,
				"low":      d.Low,
				"domains":  d.Domains,
				"top":      d.Top,
			},
		},
	}
	if d.ReportURL != "" {
		payload["links"] = []map[string]string{{"href": d.ReportURL, "text": "Full report"}}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal pagerduty payload: %w", err)
	}

	target := s.URL
	if target == "" {
		target = pdEventsAPIURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post to pagerduty: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pagerduty returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	return nil
}
