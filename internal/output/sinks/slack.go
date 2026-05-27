package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SlackSink posts an incoming-webhook payload to Slack with severity-coded
// formatting. The payload uses Slack's Block Kit: a header, a context line
// with provider+timestamp, and a per-finding section (capped to keep messages
// small).
type SlackSink struct {
	WebhookURL string
	// HTTPClient is optional; defaults to a 10-second-timeout client.
	HTTPClient *http.Client
}

func (s *SlackSink) Name() string { return "slack" }

func (s *SlackSink) Send(ctx context.Context, d Digest) error {
	if _, err := url.ParseRequestURI(s.WebhookURL); err != nil {
		return fmt.Errorf("invalid Slack webhook URL: %w", err)
	}
	payload := buildSlackPayload(d)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
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
		return fmt.Errorf("post to slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("slack returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func buildSlackPayload(d Digest) map[string]interface{} {
	severity := d.WorstSeverity()
	emoji := severityEmoji(severity)

	header := fmt.Sprintf("%s %s — %d findings on %s",
		emoji, d.Source, d.TotalFindings, d.Provider,
	)

	contextLine := fmt.Sprintf("worst: %s • %d critical / %d high / %d medium / %d low • %s",
		severity, d.Critical, d.High, d.Medium, d.Low,
		d.Timestamp.UTC().Format(time.RFC3339),
	)

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{"type": "plain_text", "text": header},
		},
		{
			"type": "context",
			"elements": []map[string]string{
				{"type": "mrkdwn", "text": contextLine},
			},
		},
	}

	if len(d.Domains) > 0 {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Domains:* %s", strings.Join(d.Domains, ", ")),
			},
		})
	}

	if len(d.Top) > 0 {
		var lines []string
		max := 10
		if len(d.Top) < max {
			max = len(d.Top)
		}
		for _, f := range d.Top[:max] {
			lines = append(lines, fmt.Sprintf("• *[%s]* `%s` `%s` — %s",
				f.Severity, f.Provider, f.Resource, truncate(f.Detail, 120),
			))
		}
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": "*Top findings:*\n" + strings.Join(lines, "\n"),
			},
		})
	}

	if d.ReportURL != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("<%s|Full report>", d.ReportURL),
			},
		})
	}

	return map[string]interface{}{
		"text":   header, // fallback for clients without Block Kit
		"blocks": blocks,
	}
}

func severityEmoji(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return ":rotating_light:"
	case "HIGH":
		return ":warning:"
	case "MEDIUM":
		return ":large_yellow_circle:"
	case "LOW":
		return ":large_blue_circle:"
	default:
		return ":information_source:"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
