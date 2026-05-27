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

// WebhookSink POSTs the Digest as application/json to a URL. The receiver is
// expected to parse the standard Digest shape — useful for custom integrations
// that don't fit Slack or PagerDuty.
type WebhookSink struct {
	URL string
	// HTTPClient is optional; defaults to a 10-second-timeout client.
	HTTPClient *http.Client
}

func (s *WebhookSink) Name() string { return "webhook" }

func (s *WebhookSink) Send(ctx context.Context, d Digest) error {
	if _, err := url.ParseRequestURI(s.URL); err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	body, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("marshal digest: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "matlock-sink")

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	return nil
}
